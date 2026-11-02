#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace lms {

class LMSException : public std::runtime_error { using std::runtime_error::runtime_error; };
class ValidationError : public LMSException { using LMSException::LMSException; };
class DatabaseError : public LMSException { using LMSException::LMSException; };

std::string nowLocal() {
    const auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return out.str();
}

std::time_t parseLocalDateTime(const std::string& value) {
    if (value.size() != 19) throw ValidationError("Date/time must use YYYY-MM-DD HH:MM:SS format.");
    std::tm parsed{};
    std::istringstream input(value);
    input >> std::get_time(&parsed, "%Y-%m-%d %H:%M:%S");
    if (input.fail() || input.peek() != std::char_traits<char>::eof())
        throw ValidationError("Date/time must use YYYY-MM-DD HH:MM:SS format.");
    const int year = parsed.tm_year, month = parsed.tm_mon, day = parsed.tm_mday;
    const int hour = parsed.tm_hour, minute = parsed.tm_min, second = parsed.tm_sec;
    parsed.tm_isdst = -1;
    const std::time_t stamp = std::mktime(&parsed);
    if (stamp == static_cast<std::time_t>(-1)) throw ValidationError("Invalid date/time.");
    std::tm checked{};
#ifdef _WIN32
    localtime_s(&checked, &stamp);
#else
    localtime_r(&stamp, &checked);
#endif
    if (checked.tm_year != year || checked.tm_mon != month || checked.tm_mday != day ||
        checked.tm_hour != hour || checked.tm_min != minute || checked.tm_sec != second)
        throw ValidationError("Invalid calendar date/time.");
    return stamp;
}

void requireText(const std::string& value, const std::string& field, std::size_t max = 200) {
    if (value.empty() || value.size() > max || value.find_first_not_of(" \t\r\n") == std::string::npos)
        throw ValidationError(field + " must contain 1-" + std::to_string(max) + " non-whitespace characters.");
}

class Statement;
class Database {
    sqlite3* db_{};
public:
    explicit Database(const std::string& path) {
        if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK) {
            std::string e = db_ ? sqlite3_errmsg(db_) : "could not allocate SQLite handle";
            if (db_) sqlite3_close(db_);
            db_ = nullptr;
            throw DatabaseError("SQLite open failed: " + e);
        }
        sqlite3_busy_timeout(db_, 5000);
        exec("PRAGMA foreign_keys = ON;");
        exec("PRAGMA journal_mode = WAL;");
        exec("PRAGMA synchronous = NORMAL;");
    }
    ~Database() { if (db_) sqlite3_close(db_); }
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;
    sqlite3* raw() const { return db_; }
    void exec(const std::string& sql) {
        char* err = nullptr;
        if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
            std::string message = err ? err : sqlite3_errmsg(db_);
            sqlite3_free(err);
            throw DatabaseError("SQLite error: " + message);
        }
    }
    void initialize() {
        exec(R"SQL(
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL UNIQUE,
 full_name TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('ADMIN','LECTURER','HOD','STUDENT')),
 salt BLOB NOT NULL,
 password_hash BLOB NOT NULL,
 active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS courses(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 code TEXT NOT NULL UNIQUE,
 title TEXT NOT NULL,
 department TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS enrollments(
 student_id INTEGER NOT NULL REFERENCES users(id),
 course_id INTEGER NOT NULL REFERENCES courses(id),
 PRIMARY KEY(student_id, course_id)
);
CREATE TABLE IF NOT EXISTS assessments(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 course_id INTEGER NOT NULL REFERENCES courses(id),
 title TEXT NOT NULL,
 available_marks REAL NOT NULL CHECK(available_marks > 0),
 due_at TEXT NOT NULL,
 allow_late INTEGER NOT NULL DEFAULT 1,
 allow_resubmission INTEGER NOT NULL DEFAULT 1,
 late_penalty_per_day REAL NOT NULL DEFAULT 10 CHECK(late_penalty_per_day BETWEEN 0 AND 100),
 max_late_days INTEGER NOT NULL DEFAULT 3 CHECK(max_late_days BETWEEN 0 AND 30),
 created_by INTEGER NOT NULL REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS extensions(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 assessment_id INTEGER NOT NULL REFERENCES assessments(id),
 student_id INTEGER REFERENCES users(id),
 new_due_at TEXT NOT NULL,
 reason TEXT NOT NULL,
 authorised_by INTEGER NOT NULL REFERENCES users(id),
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS submissions(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 assessment_id INTEGER NOT NULL REFERENCES assessments(id),
 student_id INTEGER NOT NULL REFERENCES users(id),
 attempt_no INTEGER NOT NULL,
 previous_submission_id INTEGER REFERENCES submissions(id),
 submitted_at TEXT NOT NULL,
 content TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('SUBMITTED','GRADED','APPROVED','RELEASED','REJECTED')),
 raw_mark REAL,
 final_mark REAL,
 feedback TEXT,
 graded_by INTEGER REFERENCES users(id),
 graded_at TEXT,
 approved_by INTEGER REFERENCES users(id),
 approved_at TEXT,
 released_at TEXT,
 UNIQUE(assessment_id, student_id, attempt_no)
);
CREATE TABLE IF NOT EXISTS audit_log(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 actor_id INTEGER REFERENCES users(id),
 action TEXT NOT NULL,
 entity_type TEXT NOT NULL,
 entity_id INTEGER NOT NULL,
 old_value TEXT,
 new_value TEXT,
 details TEXT,
 occurred_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_submission_student ON submissions(student_id, assessment_id, attempt_no);
CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_type, entity_id);
)SQL");
    }
};

class Transaction {
    Database& db_;
    bool committed_ = false;
public:
    explicit Transaction(Database& db) : db_(db) { db_.exec("BEGIN IMMEDIATE;"); }
    void commit() { db_.exec("COMMIT;"); committed_ = true; }
    ~Transaction() { if (!committed_) { try { db_.exec("ROLLBACK;"); } catch (...) {} } }
    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;
};

class Statement {
    sqlite3_stmt* stmt_{};
public:
    Statement(Database& db, const std::string& sql) {
        if (sqlite3_prepare_v2(db.raw(), sql.c_str(), -1, &stmt_, nullptr) != SQLITE_OK)
            throw DatabaseError("SQL prepare failed: " + std::string(sqlite3_errmsg(db.raw())));
    }
    ~Statement() { if (stmt_) sqlite3_finalize(stmt_); }
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;
    void bind(int i, const std::string& v) { if (sqlite3_bind_text(stmt_, i, v.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) fail(); }
    void bind(int i, int v) { if (sqlite3_bind_int(stmt_, i, v) != SQLITE_OK) fail(); }
    void bind(int i, double v) { if (sqlite3_bind_double(stmt_, i, v) != SQLITE_OK) fail(); }
    void bindNull(int i) { if (sqlite3_bind_null(stmt_, i) != SQLITE_OK) fail(); }
    void bindBlob(int i, const std::vector<unsigned char>& v) { if (sqlite3_bind_blob(stmt_, i, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT) != SQLITE_OK) fail(); }
    bool step() { const int rc = sqlite3_step(stmt_); if (rc == SQLITE_ROW) return true; if (rc == SQLITE_DONE) return false; fail(); return false; }
    int integer(int c) const { return sqlite3_column_int(stmt_, c); }
    double real(int c) const { return sqlite3_column_double(stmt_, c); }
    std::string string(int c) const { const auto* p = sqlite3_column_text(stmt_, c); return p ? reinterpret_cast<const char*>(p) : ""; }
    std::vector<unsigned char> blob(int c) const {
        const auto* p = static_cast<const unsigned char*>(sqlite3_column_blob(stmt_, c));
        const int n = sqlite3_column_bytes(stmt_, c);
        return p && n > 0 ? std::vector<unsigned char>(p, p + n) : std::vector<unsigned char>{};
    }
    int changes(Database& db) const { return sqlite3_changes(db.raw()); }
private:
    [[noreturn]] void fail() { throw DatabaseError("SQLite statement failed: " + std::string(sqlite3_errmsg(sqlite3_db_handle(stmt_)))); }
};

class PasswordHasher {
    static constexpr int ITERATIONS = 600000;
public:
    static std::pair<std::vector<unsigned char>, std::vector<unsigned char>> create(const std::string& password) {
        if (password.size() < 10 || password.size() > 256) throw ValidationError("Password must be 10-256 characters.");
        std::vector<unsigned char> salt(16), hash(32);
        if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) throw LMSException("Secure salt generation failed.");
        if (!PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()), salt.data(), static_cast<int>(salt.size()), ITERATIONS, EVP_sha256(), static_cast<int>(hash.size()), hash.data()))
            throw LMSException("Password hashing failed.");
        return {salt, hash};
    }
    static bool verify(const std::string& password, const std::vector<unsigned char>& salt, const std::vector<unsigned char>& expected) {
        if (salt.empty() || expected.empty() || password.size() > 256) return false;
        std::vector<unsigned char> actual(expected.size());
        if (!PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()), salt.data(), static_cast<int>(salt.size()), ITERATIONS, EVP_sha256(), static_cast<int>(actual.size()), actual.data())) return false;
        return CRYPTO_memcmp(actual.data(), expected.data(), actual.size()) == 0;
    }
};

enum class Role { Admin, Lecturer, HoD, Student };
std::string roleName(Role r) {
    switch (r) { case Role::Admin: return "ADMIN"; case Role::Lecturer: return "LECTURER"; case Role::HoD: return "HOD"; case Role::Student: return "STUDENT"; }
    throw ValidationError("Unknown role.");
}
Role parseRole(const std::string& s) {
    if (s == "ADMIN") return Role::Admin;
    if (s == "LECTURER") return Role::Lecturer;
    if (s == "HOD") return Role::HoD;
    if (s == "STUDENT") return Role::Student;
    throw ValidationError("Invalid role.");
}

class User {
protected:
    int id_; std::string username_, fullName_;
public:
    User(int id, std::string username, std::string fullName) : id_(id), username_(std::move(username)), fullName_(std::move(fullName)) {}
    virtual ~User() = default;
    int id() const { return id_; }
    const std::string& username() const { return username_; }
    const std::string& fullName() const { return fullName_; }
    virtual Role role() const = 0;
    virtual bool canManageUsers() const { return false; }
    virtual bool canManageAssessments() const { return false; }
    virtual bool canModerate() const { return false; }
    virtual bool canSubmit() const { return false; }
};
class Administrator final : public User { public: using User::User; Role role() const override { return Role::Admin; } bool canManageUsers() const override { return true; } };
class Lecturer final : public User { public: using User::User; Role role() const override { return Role::Lecturer; } bool canManageAssessments() const override { return true; } };
class HeadOfDepartment final : public User { public: using User::User; Role role() const override { return Role::HoD; } bool canModerate() const override { return true; } };
class Student final : public User { public: using User::User; Role role() const override { return Role::Student; } bool canSubmit() const override { return true; } };

// Factory pattern: all role-specific User objects are constructed centrally.
class UserFactory {
public:
    static std::unique_ptr<User> create(Role role, int id, const std::string& username, const std::string& name) {
        switch (role) {
            case Role::Admin: return std::make_unique<Administrator>(id, username, name);
            case Role::Lecturer: return std::make_unique<Lecturer>(id, username, name);
            case Role::HoD: return std::make_unique<HeadOfDepartment>(id, username, name);
            case Role::Student: return std::make_unique<Student>(id, username, name);
        }
        throw ValidationError("Unsupported user role.");
    }
};

class AuditRepository {
    Database& db_;
public:
    explicit AuditRepository(Database& db) : db_(db) {}
    void record(int actor, const std::string& action, const std::string& type, int id,
                const std::string& oldValue = "", const std::string& newValue = "", const std::string& details = "") {
        Statement q(db_, "INSERT INTO audit_log(actor_id,action,entity_type,entity_id,old_value,new_value,details,occurred_at) VALUES(?,?,?,?,?,?,?,?)");
        q.bind(1, actor); q.bind(2, action); q.bind(3, type); q.bind(4, id);
        q.bind(5, oldValue); q.bind(6, newValue); q.bind(7, details); q.bind(8, nowLocal()); q.step();
    }
};

struct AuditEvent {
    int actor; std::string action, entityType; int entityId;
    std::string oldValue, newValue, details;
};
class IEventObserver {
public:
    virtual ~IEventObserver() = default;
    virtual void onEvent(const AuditEvent& event) = 0;
};
class AuditObserver final : public IEventObserver {
    AuditRepository& audit_;
public:
    explicit AuditObserver(AuditRepository& audit) : audit_(audit) {}
    void onEvent(const AuditEvent& e) override {
        audit_.record(e.actor, e.action, e.entityType, e.entityId, e.oldValue, e.newValue, e.details);
    }
};
class EventPublisher {
    std::vector<IEventObserver*> observers_;
public:
    void attach(IEventObserver& observer) { observers_.push_back(&observer); }
    void publish(const AuditEvent& event) {
        for (auto* observer : observers_) observer->onEvent(event);
    }
};

class UserRepository {
    Database& db_;
public:
    explicit UserRepository(Database& db) : db_(db) {}
    int create(const std::string& username, const std::string& name, Role role, const std::string& password) {
        requireText(username, "Username", 60); requireText(name, "Full name", 120);
        const auto credentials = PasswordHasher::create(password);
        Statement q(db_, "INSERT INTO users(username,full_name,role,salt,password_hash) VALUES(?,?,?,?,?)");
        q.bind(1, username); q.bind(2, name); q.bind(3, roleName(role)); q.bindBlob(4, credentials.first); q.bindBlob(5, credentials.second); q.step();
        return static_cast<int>(sqlite3_last_insert_rowid(db_.raw()));
    }
    std::unique_ptr<User> authenticate(const std::string& username, const std::string& password) {
        Statement q(db_, "SELECT id,username,full_name,role,salt,password_hash FROM users WHERE username=? AND active=1");
        q.bind(1, username);
        if (!q.step() || !PasswordHasher::verify(password, q.blob(4), q.blob(5))) return nullptr;
        return UserFactory::create(parseRole(q.string(3)), q.integer(0), q.string(1), q.string(2));
    }
    bool exists(int id) {
        Statement q(db_, "SELECT 1 FROM users WHERE id=? AND active=1"); q.bind(1, id); return q.step();
    }
    bool isStudent(int id) {
        Statement q(db_, "SELECT 1 FROM users WHERE id=? AND role='STUDENT' AND active=1"); q.bind(1, id); return q.step();
    }
    void changePassword(int id, const std::string& password) {
        const auto credentials = PasswordHasher::create(password);
        Statement q(db_, "UPDATE users SET salt=?,password_hash=? WHERE id=? AND active=1");
        q.bindBlob(1, credentials.first); q.bindBlob(2, credentials.second); q.bind(3, id); q.step();
        if (q.changes(db_) != 1) throw ValidationError("User account not found.");
    }
    bool createInitialAdminIfEmpty() {
        Statement q(db_, "SELECT COUNT(*) FROM users"); q.step();
        if (q.integer(0) != 0) return false;
        const auto credentials = PasswordHasher::create("ChangeMe!123");
        Statement ins(db_, "INSERT INTO users(username,full_name,role,salt,password_hash) VALUES(?,?,?,?,?)");
        ins.bind(1, "admin"); ins.bind(2, "System Administrator"); ins.bind(3, "ADMIN");
        ins.bindBlob(4, credentials.first); ins.bindBlob(5, credentials.second); ins.step();
        return true;
    }
};

class CourseRepository {
    Database& db_;
public:
    explicit CourseRepository(Database& db) : db_(db) {}
    int create(const std::string& code, const std::string& title, const std::string& department) {
        requireText(code, "Course code", 30); requireText(title, "Course title", 160); requireText(department, "Department", 120);
        Statement q(db_, "INSERT INTO courses(code,title,department) VALUES(?,?,?)");
        q.bind(1, code); q.bind(2, title); q.bind(3, department); q.step();
        return static_cast<int>(sqlite3_last_insert_rowid(db_.raw()));
    }
    void enroll(int student, int course) {
        Statement q(db_, "INSERT INTO enrollments(student_id,course_id) VALUES(?,?)");
        q.bind(1, student); q.bind(2, course); q.step();
    }
    bool isEnrolledForAssessment(int student, int assessment) {
        Statement q(db_, "SELECT 1 FROM enrollments e JOIN assessments a ON a.course_id=e.course_id WHERE e.student_id=? AND a.id=?");
        q.bind(1, student); q.bind(2, assessment); return q.step();
    }
};

class IAssessmentPolicy {
public:
    virtual ~IAssessmentPolicy() = default;
    virtual double finalMark(double raw, double available, int lateDays) const = 0;
};
class StandardLatePenaltyPolicy final : public IAssessmentPolicy {
    double percent_; int maxDays_;
public:
    StandardLatePenaltyPolicy(double percent, int maxDays) : percent_(percent), maxDays_(maxDays) {}
    double finalMark(double raw, double available, int lateDays) const override {
        if (lateDays > maxDays_) return 0.0;
        const double deduction = available * (percent_ / 100.0) * static_cast<double>(lateDays);
        return std::clamp(raw - deduction, 0.0, available);
    }
};

class AssessmentRepository {
    Database& db_;
public:
    explicit AssessmentRepository(Database& db) : db_(db) {}
    int create(int course, const std::string& title, double marks, const std::string& due, int late, int resubmit, int creator) {
        requireText(title, "Assessment title", 160); (void)parseLocalDateTime(due);
        if (marks <= 0 || !std::isfinite(marks)) throw ValidationError("Available marks must be positive.");
        Statement q(db_, "INSERT INTO assessments(course_id,title,available_marks,due_at,allow_late,allow_resubmission,created_by) VALUES(?,?,?,?,?,?,?)");
        q.bind(1, course); q.bind(2, title); q.bind(3, marks); q.bind(4, due); q.bind(5, late); q.bind(6, resubmit); q.bind(7, creator); q.step();
        return static_cast<int>(sqlite3_last_insert_rowid(db_.raw()));
    }
    struct Rules { double available; std::string due; bool allowLate; bool allowResubmit; double penalty; int maxDays; };
    Rules getRules(int id) {
        Statement q(db_, "SELECT available_marks,due_at,allow_late,allow_resubmission,late_penalty_per_day,max_late_days FROM assessments WHERE id=?"); q.bind(1, id);
        if (!q.step()) throw ValidationError("Assessment not found.");
        return {q.real(0), q.string(1), q.integer(2) != 0, q.integer(3) != 0, q.real(4), q.integer(5)};
    }
    std::string effectiveDeadline(int assessment, int student) {
        Statement q(db_, "SELECT new_due_at FROM extensions WHERE assessment_id=? AND (student_id=? OR student_id IS NULL) ORDER BY CASE WHEN student_id=? THEN 0 ELSE 1 END, new_due_at DESC LIMIT 1");
        q.bind(1, assessment); q.bind(2, student); q.bind(3, student);
        if (q.step()) return q.string(0);
        return getRules(assessment).due;
    }
    void extend(int assessment, int studentOrZero, const std::string& due, const std::string& reason, int actor) {
        (void)parseLocalDateTime(due); requireText(reason, "Extension reason", 500);
        Statement q(db_, "INSERT INTO extensions(assessment_id,student_id,new_due_at,reason,authorised_by,created_at) VALUES(?,?,?,?,?,?)");
        q.bind(1, assessment); if (studentOrZero == 0) q.bindNull(2); else q.bind(2, studentOrZero);
        q.bind(3, due); q.bind(4, reason); q.bind(5, actor); q.bind(6, nowLocal()); q.step();
    }
};

class SubmissionRepository {
    Database& db_;
public:
    explicit SubmissionRepository(Database& db) : db_(db) {}
    struct Previous { int id; int attempt; };
    Previous latest(int assessment, int student) {
        Statement q(db_, "SELECT id,attempt_no FROM submissions WHERE assessment_id=? AND student_id=? ORDER BY attempt_no DESC LIMIT 1");
        q.bind(1, assessment); q.bind(2, student);
        if (q.step()) return {q.integer(0), q.integer(1)};
        return {0, 0};
    }
    int submit(int assessment, int student, const std::string& content, const std::string& timestamp) {
        requireText(content, "Submission content", 1000000);
        const auto prev = latest(assessment, student);
        Statement q(db_, "INSERT INTO submissions(assessment_id,student_id,attempt_no,previous_submission_id,submitted_at,content,status) VALUES(?,?,?,?,?,?,'SUBMITTED')");
        q.bind(1, assessment); q.bind(2, student); q.bind(3, prev.attempt + 1);
        if (prev.id == 0) q.bindNull(4); else q.bind(4, prev.id);
        q.bind(5, timestamp); q.bind(6, content); q.step();
        return static_cast<int>(sqlite3_last_insert_rowid(db_.raw()));
    }
    struct Submission { int id; int assessment; int student; std::string submittedAt; std::string status; double raw; double final; };
    Submission get(int id) {
        Statement q(db_, "SELECT id,assessment_id,student_id,submitted_at,status,COALESCE(raw_mark,0),COALESCE(final_mark,0) FROM submissions WHERE id=?"); q.bind(1, id);
        if (!q.step()) throw ValidationError("Submission not found.");
        return {q.integer(0), q.integer(1), q.integer(2), q.string(3), q.string(4), q.real(5), q.real(6)};
    }
    void grade(int id, int actor, double raw, double final, const std::string& feedback) {
        Statement q(db_, "UPDATE submissions SET raw_mark=?,final_mark=?,feedback=?,graded_by=?,graded_at=?,status='GRADED' WHERE id=? AND status IN ('SUBMITTED','GRADED')");
        q.bind(1, raw); q.bind(2, final); q.bind(3, feedback); q.bind(4, actor); q.bind(5, nowLocal()); q.bind(6, id); q.step();
        if (q.changes(db_) != 1) throw ValidationError("Submission is not awaiting grading.");
    }
    void approve(int id, int actor) {
        Statement q(db_, "UPDATE submissions SET approved_by=?,approved_at=?,status='APPROVED' WHERE id=? AND status='GRADED'");
        q.bind(1, actor); q.bind(2, nowLocal()); q.bind(3, id); q.step();
        if (q.changes(db_) != 1) throw ValidationError("Only graded submissions can be approved.");
    }
    void release(int id) {
        Statement q(db_, "UPDATE submissions SET released_at=?,status='RELEASED' WHERE id=? AND status='APPROVED'");
        q.bind(1, nowLocal()); q.bind(2, id); q.step();
        if (q.changes(db_) != 1) throw ValidationError("Only approved submissions can be released.");
    }
    std::vector<Submission> releasedForStudent(int student) {
        Statement q(db_, "SELECT id,assessment_id,student_id,submitted_at,status,COALESCE(raw_mark,0),COALESCE(final_mark,0) FROM submissions WHERE student_id=? AND status='RELEASED' ORDER BY id DESC");
        q.bind(1, student); std::vector<Submission> rows;
        while (q.step()) rows.push_back({q.integer(0), q.integer(1), q.integer(2), q.string(3), q.string(4), q.real(5), q.real(6)});
        return rows;
    }
};

class LMSService {
    Database& db_; UserRepository users_; CourseRepository courses_; AssessmentRepository assessments_; SubmissionRepository submissions_; AuditRepository audit_; AuditObserver auditObserver_; EventPublisher events_;
public:
    explicit LMSService(Database& db) : db_(db), users_(db), courses_(db), assessments_(db), submissions_(db), audit_(db), auditObserver_(audit_) { events_.attach(auditObserver_); }
    UserRepository& users() { return users_; }
    int createUser(const User& actor, const std::string& username, const std::string& name, Role role, const std::string& password) {
        if (!actor.canManageUsers()) throw ValidationError("Only administrators can create accounts.");
        Transaction tx(db_);
        const int id = users_.create(username, name, role, password); events_.publish({actor.id(), "USER_CREATED", "USER", id, "", roleName(role), ""}); tx.commit(); return id;
    }
    int createCourse(const User& actor, const std::string& code, const std::string& title, const std::string& department) {
        if (!actor.canManageUsers()) throw ValidationError("Only administrators can create courses.");
        Transaction tx(db_);
        const int id = courses_.create(code, title, department);
        events_.publish({actor.id(), "COURSE_CREATED", "COURSE", id, "", code + " - " + title, ""});
        tx.commit(); return id;
    }
    void enrollStudent(const User& actor, int student, int course) {
        if (!actor.canManageUsers()) throw ValidationError("Only administrators can manage enrolments.");
        if (!users_.exists(student)) throw ValidationError("Student account not found.");
        Transaction tx(db_);
        courses_.enroll(student, course);
        events_.publish({actor.id(), "STUDENT_ENROLLED", "COURSE", course, "", "student=" + std::to_string(student), ""});
        tx.commit();
    }
    int createAssessment(const User& actor, int course, const std::string& title, double marks, const std::string& due, bool late, bool resubmit) {
        if (!actor.canManageAssessments()) throw ValidationError("Only lecturers can create assessments.");
        Transaction tx(db_);
        const int id = assessments_.create(course, title, marks, due, late ? 1 : 0, resubmit ? 1 : 0, actor.id());
        events_.publish({actor.id(), "ASSESSMENT_CREATED", "ASSESSMENT", id, "", title, ""}); tx.commit(); return id;
    }
    void grantExtension(const User& actor, int assessment, int studentOrZero, const std::string& due, const std::string& reason) {
        if (!actor.canManageAssessments()) throw ValidationError("Only lecturers can authorise extensions.");
        if (studentOrZero != 0 && !users_.isStudent(studentOrZero)) throw ValidationError("Student account not found or selected account is not a student.");
        assessments_.getRules(assessment);
        const std::string currentDeadline = assessments_.effectiveDeadline(assessment, studentOrZero);
        if (due <= currentDeadline) throw ValidationError("An extension must move the effective deadline later.");
        Transaction tx(db_);
        assessments_.extend(assessment, studentOrZero, due, reason, actor.id());
        events_.publish({actor.id(), "EXTENSION_GRANTED", "ASSESSMENT", assessment, "", due, reason + (studentOrZero == 0 ? " [whole class]" : " [student " + std::to_string(studentOrZero) + "]")});
        tx.commit();
    }
    int submit(const User& actor, int assessment, const std::string& content) {
        if (!actor.canSubmit()) throw ValidationError("Only students can submit work.");
        const auto rules = assessments_.getRules(assessment);
        // Enrolment is checked inside the data-access layer.
        if (!courses_.isEnrolledForAssessment(actor.id(), assessment)) throw ValidationError("You are not enrolled in the course for this assessment.");
        const auto previous = submissions_.latest(assessment, actor.id());
        if (previous.attempt > 0 && !rules.allowResubmit) throw ValidationError("Resubmissions are disabled for this assessment.");
        const std::string stamp = nowLocal();
        const std::string deadline = assessments_.effectiveDeadline(assessment, actor.id());
        const int lateDays = daysLate(stamp, deadline);
        if (lateDays > 0 && !rules.allowLate) throw ValidationError("Late submissions are not permitted.");
        if (lateDays > rules.maxDays) throw ValidationError("Submission window has closed; maximum late period exceeded.");
        Transaction tx(db_);
        const int id = submissions_.submit(assessment, actor.id(), content, stamp);
        events_.publish({actor.id(), "SUBMISSION_CREATED", "SUBMISSION", id, "", "attempt " + std::to_string(previous.attempt + 1), "late_days=" + std::to_string(lateDays)});
        tx.commit(); return id;
    }
    void grade(const User& actor, int submissionId, double raw, const std::string& feedback) {
        if (!actor.canManageAssessments()) throw ValidationError("Only lecturers can grade submissions.");
        const auto s = submissions_.get(submissionId); const auto rules = assessments_.getRules(s.assessment);
        if (s.status != "SUBMITTED" && s.status != "GRADED") throw ValidationError("Only submitted or previously graded work can be marked.");
        if (!std::isfinite(raw) || raw < 0 || raw > rules.available) throw ValidationError("Mark must be between 0 and available marks.");
        const int lateDays = daysLate(s.submittedAt, assessments_.effectiveDeadline(s.assessment, s.student));
        StandardLatePenaltyPolicy policy(rules.penalty, rules.maxDays);
        const double final = policy.finalMark(raw, rules.available, lateDays);
        Transaction tx(db_);
        submissions_.grade(submissionId, actor.id(), raw, final, feedback);
        events_.publish({actor.id(), "MARK_CHANGED", "SUBMISSION", submissionId, s.status == "GRADED" ? std::to_string(s.final) : "ungraded", std::to_string(final), "raw=" + std::to_string(raw) + "; late_days=" + std::to_string(lateDays) + "; penalty_percent_per_day=" + std::to_string(rules.penalty)});
        tx.commit();
    }
    void moderate(const User& actor, int submissionId) {
        if (!actor.canModerate()) throw ValidationError("Only the HoD can approve marks.");
        const auto s = submissions_.get(submissionId); Transaction tx(db_); submissions_.approve(submissionId, actor.id());
        events_.publish({actor.id(), "MARK_APPROVED", "SUBMISSION", submissionId, "GRADED", "APPROVED", "assessment=" + std::to_string(s.assessment)}); tx.commit();
    }
    void release(const User& actor, int submissionId) {
        if (!actor.canModerate()) throw ValidationError("Only the HoD can release moderated marks.");
        Transaction tx(db_); submissions_.release(submissionId); events_.publish({actor.id(), "MARK_RELEASED", "SUBMISSION", submissionId, "APPROVED", "RELEASED", ""}); tx.commit();
    }
    void changePassword(const User& actor, const std::string& password) {
        Transaction tx(db_); users_.changePassword(actor.id(), password);
        events_.publish({actor.id(), "PASSWORD_CHANGED", "USER", actor.id(), "", "", ""}); tx.commit();
    }
    std::vector<SubmissionRepository::Submission> results(const User& actor) {
        if (!actor.canSubmit()) throw ValidationError("Only students can view student results.");
        return submissions_.releasedForStudent(actor.id());
    }
private:
    static int daysLate(const std::string& submitted, const std::string& deadline) {
        const auto ta = parseLocalDateTime(submitted);
        const auto tb = parseLocalDateTime(deadline);
        const double seconds = std::difftime(ta, tb);
        if (seconds <= 0) return 0;
        return static_cast<int>(std::ceil(seconds / 86400.0));
    }
};

std::string ask(const std::string& prompt) { std::cout << prompt; std::string v; std::getline(std::cin, v); return v; }
int askInt(const std::string& prompt) {
    const auto s = ask(prompt); try { std::size_t n = 0; const int v = std::stoi(s, &n); if (n != s.size()) throw std::invalid_argument("x"); return v; }
    catch (...) { throw ValidationError("Please enter a valid whole number."); }
}
double askDouble(const std::string& prompt) {
    const auto s = ask(prompt); try { std::size_t n = 0; const double v = std::stod(s, &n); if (n != s.size() || !std::isfinite(v)) throw std::invalid_argument("x"); return v; }
    catch (...) { throw ValidationError("Please enter a valid number."); }
}
void ensureBootstrap(LMSService& service) {
    if (service.users().createInitialAdminIfEmpty())
        std::cout << "Initial administrator created: admin / ChangeMe!123\nChange this password immediately using menu option 11.\n";
}

void runMenu(LMSService& service, User& user) {
    while (true) {
        std::cout << "\nLogged in: " << user.fullName() << " [" << roleName(user.role()) << "]\n"
                  << "1. Create user (Administrator)\n2. Create course (Administrator)\n3. Enrol student (Administrator)\n"
                  << "4. Create assessment (Lecturer)\n5. Grant extension (Lecturer)\n"
                  << "6. Submit/resubmit work (Student)\n7. Grade submission (Lecturer)\n8. Approve mark (HoD)\n"
                  << "9. Release mark (HoD)\n10. View released results (Student)\n11. Change password\n0. Logout\n";
        try {
            const int choice = askInt("Choice: ");
            if (choice == 0) return;
            if (choice == 1) {
                const std::string username = ask("Username: "), name = ask("Full name: ");
                const std::string r = ask("Role (STUDENT/LECTURER/HOD/ADMIN): ");
                const std::string pw = ask("Password (10+ characters): ");
                const int id = service.createUser(user, username, name, parseRole(r), pw); std::cout << "Created user ID " << id << "\n";
            } else if (choice == 2) {
                std::string code = ask("Course code: "), title = ask("Course title: "), department = ask("Department: ");
                std::cout << "Created course ID " << service.createCourse(user, code, title, department) << "\n";
            } else if (choice == 3) {
                int student = askInt("Student user ID: "), course = askInt("Course ID: ");
                service.enrollStudent(user, student, course); std::cout << "Student enrolled.\n";
            } else if (choice == 4) {
                int course = askInt("Existing course ID: "); std::string title = ask("Assessment title: ");
                double marks = askDouble("Available marks: "); std::string due = ask("Deadline (YYYY-MM-DD HH:MM:SS): ");
                bool late = ask("Allow late submissions? (y/n): ") == "y"; bool resubmit = ask("Allow resubmissions? (y/n): ") == "y";
                std::cout << "Created assessment ID " << service.createAssessment(user, course, title, marks, due, late, resubmit) << "\n";
            } else if (choice == 5) {
                int assessment = askInt("Assessment ID: "); int student = askInt("Student ID (0 = whole class): ");
                std::string due = ask("New deadline (YYYY-MM-DD HH:MM:SS): "); std::string reason = ask("Reason: ");
                service.grantExtension(user, assessment, student, due, reason); std::cout << "Extension recorded.\n";
            } else if (choice == 6) {
                int assessment = askInt("Assessment ID: "); std::string content = ask("Submission text/content: ");
                std::cout << "Submission recorded with ID " << service.submit(user, assessment, content) << "\n";
            } else if (choice == 7) {
                int id = askInt("Submission ID: "); double mark = askDouble("Raw mark: "); std::string feedback = ask("Feedback: ");
                service.grade(user, id, mark, feedback); std::cout << "Mark saved; it remains hidden pending HoD moderation.\n";
            } else if (choice == 8) {
                int id = askInt("Submission ID: "); service.moderate(user, id); std::cout << "Mark approved.\n";
            } else if (choice == 9) {
                int id = askInt("Submission ID: "); service.release(user, id); std::cout << "Mark released to student.\n";
            } else if (choice == 10) {
                for (const auto& s : service.results(user)) std::cout << "Submission " << s.id << " | Assessment " << s.assessment << " | Final mark " << s.final << "\n";
            } else if (choice == 11) {
                const std::string pw = ask("New password (10+ characters): ");
                service.changePassword(user, pw); std::cout << "Password updated. Please log in again next time with the new password.\n";
            } else std::cout << "Unknown menu choice.\n";
        } catch (const std::exception& e) { std::cerr << "Operation failed: " << e.what() << "\n"; }
    }
}

} // namespace lms

int main() {
    try {
        lms::Database db("offline_lms.sqlite3"); db.initialize();
        lms::LMSService service(db); lms::ensureBootstrap(service);
        std::cout << "\n=== Moderated Offline LMS ===\n";
        while (true) {
            try {
                const std::string username = lms::ask("Username (or 'exit'): ");
                if (username == "exit") break;
                const std::string password = lms::ask("Password: ");
                auto user = service.users().authenticate(username, password);
                if (!user) { std::cout << "Invalid credentials or inactive account.\n"; continue; }
                lms::runMenu(service, *user);
            } catch (const std::exception& e) { std::cerr << "Login error: " << e.what() << "\n"; }
        }
    } catch (const std::exception& e) { std::cerr << "Fatal startup error: " << e.what() << "\n"; return 1; }
    return 0;
}
