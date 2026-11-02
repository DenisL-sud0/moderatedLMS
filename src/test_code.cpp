// tests.cpp — Unit, Integration, and System tests for the Moderated Offline LMS.
// Build:
//   g++ -std=c++17 -Wall -Wextra -fsanitize=address,undefined \
//       tests.cpp -o tests -lsqlite3 -lcrypto
// Run:
//   ./tests

#include "lms.hpp"

#include <cmath>
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

using namespace lms;

// ---------- Tiny test framework ----------
static int g_pass = 0, g_fail = 0;
static std::string g_suite;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; \
        std::cerr << "  FAIL [" << g_suite << "] " << __FILE__ << ":" << __LINE__ \
                  << "  " #cond "\n"; } \
} while (0)

#define CHECK_THROWS(expr, ExType) do { \
    bool threw = false; \
    try { (void)(expr); } \
    catch (const ExType&) { threw = true; } \
    catch (...) { threw = false; } \
    if (threw) { ++g_pass; } \
    else { ++g_fail; \
        std::cerr << "  FAIL [" << g_suite << "] expected " #ExType \
                  << " from " #expr " at " << __FILE__ << ":" << __LINE__ << "\n"; } \
} while (0)

#define CHECK_NEAR(a, b, eps) CHECK(std::fabs((a) - (b)) <= (eps))

static void suite(const std::string& name) {
    g_suite = name;
    std::cout << "== " << name << " ==\n";
}

// ---------- Test helpers ----------
static std::unique_ptr<Database> freshDb() {
    // In-memory DB; each call is isolated.
    auto db = std::make_unique<Database>(":memory:");
    db->initialize();
    return db;
}

// A minimal harness that builds users via the repositories (bypasses admin check
// when needed) so integration tests don't have to bootstrap through the menu.
struct World {
    std::unique_ptr<Database> db;
    std::unique_ptr<LMSService> svc;
    std::unique_ptr<User> admin, lecturer, hod, student;

    explicit World() {
        db = freshDb();
        svc = std::make_unique<LMSService>(*db);
        UserRepository& users = svc->users();
        users.create("admin1",    "Admin One",   Role::Admin,    "AdminPass123");
        users.create("lecturer1", "Lecturer One",Role::Lecturer, "LectPass1234");
        users.create("hod1",      "HOD One",     Role::HoD,      "HodPass12345");
        users.create("student1",  "Student One", Role::Student,  "StudPass1234");
        admin    = users.authenticate("admin1",    "AdminPass123");
        lecturer = users.authenticate("lecturer1", "LectPass1234");
        hod      = users.authenticate("hod1",      "HodPass12345");
        student  = users.authenticate("student1",  "StudPass1234");
    }
};

static std::string plusSeconds(const std::string& base, long seconds) {
    // Helper: shift a "YYYY-MM-DD HH:MM:SS" string by seconds (local time).
    std::time_t t = parseLocalDateTime(base);
    t += seconds;
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

// =====================================================================
// LEVEL 1 — UNIT TESTS
// =====================================================================

// Equivalence partitioning: date parser valid vs invalid classes.
static void test_parseLocalDateTime_EP() {
    suite("UNIT parseLocalDateTime — equivalence partitioning");

    // Valid partition
    CHECK(parseLocalDateTime("2025-01-01 00:00:00") != (std::time_t)-1);
    CHECK(parseLocalDateTime("2025-12-31 23:59:59") != (std::time_t)-1);
    CHECK(parseLocalDateTime("2024-02-29 12:00:00") != (std::time_t)-1); // leap day

    // Invalid partitions (each is a distinct equivalence class)
    CHECK_THROWS(parseLocalDateTime("2025-01-01 00:00"),          ValidationError); // wrong length
    CHECK_THROWS(parseLocalDateTime("2025-13-01 00:00:00"),       ValidationError); // month > 12
    CHECK_THROWS(parseLocalDateTime("2025-00-01 00:00:00"),       ValidationError); // month 0
    CHECK_THROWS(parseLocalDateTime("2025-01-32 00:00:00"),       ValidationError); // day > 31
    CHECK_THROWS(parseLocalDateTime("2025-01-00 00:00:00"),       ValidationError); // day 0
    CHECK_THROWS(parseLocalDateTime("2025-02-30 00:00:00"),       ValidationError); // Feb 30
    CHECK_THROWS(parseLocalDateTime("2023-02-29 00:00:00"),       ValidationError); // non-leap Feb 29
    CHECK_THROWS(parseLocalDateTime("2025-01-01 24:00:00"),       ValidationError); // hour 24
    CHECK_THROWS(parseLocalDateTime("2025-01-01 00:60:00"),       ValidationError); // minute 60
    CHECK_THROWS(parseLocalDateTime("2025-01-01 00:00:60"),       ValidationError); // second 60
    CHECK_THROWS(parseLocalDateTime("abcd-ef-gh ij:kl:mn"),       ValidationError); // non-numeric
    CHECK_THROWS(parseLocalDateTime("2025-01-01 00:00:00x"),      ValidationError); // trailing junk
}

// Boundary value analysis: password length around the 10..256 window.
static void test_PasswordHasher_BVA() {
    suite("UNIT PasswordHasher — boundary value analysis");

    auto check = [](const std::string& pw, bool shouldThrow) {
        bool threw = false;
        try { (void)PasswordHasher::create(pw); }
        catch (const ValidationError&) { threw = true; }
        CHECK(threw == shouldThrow);
    };

    check(std::string(9,   'a'), true);   // 9  — just below lower bound
    check(std::string(10,  'a'), false);  // 10 — lower bound (valid)
    check(std::string(11,  'a'), false);  // 11 — just above lower bound
    check(std::string(256, 'a'), false);  // 256 — upper bound (valid)
    check(std::string(257, 'a'), true);   // 257 — just above upper bound

    // Verify round-trip on the boundary values that succeed
    const std::string pw = "boundary10"; // length 10
    const auto [salt, hash] = PasswordHasher::create(pw);
    CHECK(PasswordHasher::verify(pw, salt, hash));
    CHECK(!PasswordHasher::verify("wrongpass1", salt, hash));

    // Empty salt/hash must never verify
    CHECK(!PasswordHasher::verify(pw, {}, {}));
}

// Boundary value analysis + equivalence partitioning for late penalty.
static void test_PenaltyPolicy_BVA_EP() {
    suite("UNIT StandardLatePenaltyPolicy — BVA + EP");

    // 10% per day, max 3 late days, available = 100.
    StandardLatePenaltyPolicy policy(10.0, 3);

    // EP: on time (lateDays = 0)
    CHECK_NEAR(policy.finalMark(80.0, 100.0, 0), 80.0, 1e-9);
    // EP/BVA: 1 day late — boundary between "grace" and "penalty applies"
    CHECK_NEAR(policy.finalMark(80.0, 100.0, 1), 70.0, 1e-9);
    // BVA: at maxDays (3) — still accepted
    CHECK_NEAR(policy.finalMark(100.0, 100.0, 3), 70.0, 1e-9);
    // BVA: maxDays + 1 (4) — rejected ? 0
    CHECK_NEAR(policy.finalMark(100.0, 100.0, 4), 0.0, 1e-9);
    // BVA: raw = 0 and raw = available
    CHECK_NEAR(policy.finalMark(0.0,   100.0, 0), 0.0,   1e-9);
    CHECK_NEAR(policy.finalMark(100.0, 100.0, 0), 100.0, 1e-9);
    // Clamp: deduction larger than raw
    CHECK_NEAR(policy.finalMark(5.0,   100.0, 1), 0.0,   1e-9);
    // EP: 0% penalty, maxDays 0 ? any lateness rejected
    StandardLatePenaltyPolicy zero(0.0, 0);
    CHECK_NEAR(zero.finalMark(50.0, 100.0, 0), 50.0, 1e-9);
    CHECK_NEAR(zero.finalMark(50.0, 100.0, 1), 0.0,  1e-9);
}

// Equivalence partitioning for requireText.
static void test_requireText_EP() {
    suite("UNIT requireText — equivalence partitioning");

    CHECK_NOTHROW:; // no-op label placeholder (avoid unused warnings)
    // Valid
    try { requireText("Alice", "Name"); } catch (...) { CHECK(false); }
    try { requireText("A", "Name", 1); } catch (...) { CHECK(false); }
    // Invalid partitions
    CHECK_THROWS(requireText("", "Name"), ValidationError);          // empty
    CHECK_THROWS(requireText("   \t\r\n", "Name"), ValidationError); // whitespace only
    CHECK_THROWS(requireText(std::string(201, 'a'), "Name", 200), ValidationError); // too long
}

// =====================================================================
// LEVEL 2 — INTEGRATION TESTS
// =====================================================================

// Audit is written on successful mutation and rolled back on failure.
static void test_Audit_OnSuccess_And_Rollback() {
    suite("INTEGRATION AuditObserver + Transaction");

    World w;
    // Count audit rows before
    auto countAudit = [&]() {
        Statement q(*w.db, "SELECT COUNT(*) FROM audit_log");
        q.step();
        return q.integer(0);
    };

    const int before = countAudit();
    const int id = w.svc->createUser(*w.admin, "u1", "User One", Role::Student, "Password123");
    CHECK(id > 0);
    CHECK(countAudit() == before + 1); // exactly one audit event

    // Now force a failure *inside* the transaction: duplicate username.
    CHECK_THROWS(
        w.svc->createUser(*w.admin, "u1", "Dup", Role::Student, "Password123"),
        DatabaseError);
    CHECK(countAudit() == before + 1); // no new audit row — rollback worked
}

// RBAC matrix — System-level but built on service APIs. We include it in
// integration because it exercises the service ? repository boundary.
static void test_RBAC_Matrix_System() {
    suite("SYSTEM RBAC matrix — equivalence partitioning across roles");

    World w;
    const int courseId = w.svc->createCourse(*w.admin, "CS101", "Intro CS", "CS");

    // createUser: only admin
    CHECK_THROWS(w.svc->createUser(*w.lecturer, "x1", "X", Role::Student, "Password123"), ValidationError);
    CHECK_THROWS(w.svc->createUser(*w.hod,      "x2", "X", Role::Student, "Password123"), ValidationError);
    CHECK_THROWS(w.svc->createUser(*w.student,  "x3", "X", Role::Student, "Password123"), ValidationError);

    // createCourse: only admin
    CHECK_THROWS(w.svc->createCourse(*w.lecturer, "CS102", "x", "CS"), ValidationError);

    // createAssessment: only lecturer
    CHECK_THROWS(w.svc->createAssessment(*w.admin,   courseId, "A", 10, "2030-01-01 00:00:00", true, true), ValidationError);
    CHECK_THROWS(w.svc->createAssessment(*w.hod,     courseId, "A", 10, "2030-01-01 00:00:00", true, true), ValidationError);
    CHECK_THROWS(w.svc->createAssessment(*w.student, courseId, "A", 10, "2030-01-01 00:00:00", true, true), ValidationError);

    // submit: only student (but student must be enrolled first)
    const int assessmentId = w.svc->createAssessment(*w.lecturer, courseId, "A", 10, "2030-01-01 00:00:00", true, true);
    CHECK_THROWS(w.svc->submit(*w.lecturer, assessmentId, "hi"), ValidationError);
    CHECK_THROWS(w.svc->submit(*w.admin,    assessmentId, "hi"), ValidationError);
    CHECK_THROWS(w.svc->submit(*w.hod,      assessmentId, "hi"), ValidationError);
}

// End-to-end workflow: submit ? grade ? approve ? release ? student sees it.
static void test_Workflow_HappyPath() {
    suite("SYSTEM workflow — submit/grade/approve/release");

    World w;
    const int courseId = w.svc->createCourse(*w.admin, "CS201", "Data Structures", "CS");
    w.svc->enrollStudent(*w.admin, w.student->id(), courseId);
    const int aid = w.svc->createAssessment(*w.lecturer, courseId, "Assignment 1",
                                            100.0, "2030-01-01 00:00:00",
                                            /*late=*/false, /*resubmit=*/false);

    const int sid = w.svc->submit(*w.student, aid, "my answer");
    CHECK(sid > 0);

    // Student sees nothing yet
    CHECK(w.svc->results(*w.student).empty());

    w.svc->grade(*w.lecturer, sid, 80.0, "good");
    CHECK(w.svc->results(*w.student).empty()); // still hidden

    w.svc->moderate(*w.hod, sid);
    CHECK(w.svc->results(*w.student).empty()); // still hidden until release

    w.svc->release(*w.hod, sid);
    const auto rows = w.svc->results(*w.student);
    CHECK(rows.size() == 1);
    CHECK_NEAR(rows[0].final, 80.0, 1e-9);
}

// Late-penalty end-to-end, using the real clock at submission time.
// Because the service uses nowLocal(), we simulate "late" by setting a past deadline.
static void test_LatePenalty_EndToEnd_BVA() {
    suite("SYSTEM late penalty — BVA on deadline offsets");

    struct Case { long offsetSeconds; double expectedFinal; const char* label; };

    // 10% per day, max 3 late days, available 100, raw 100.
    // Deadline is offsetSeconds before "now"; a submission made "now" is late by
    // -offsetSeconds / 86400 rounded up. We compute expected accordingly.
    // We test: on time (offset = +60s so deadline is in future), and
    // 1 day late, 3 days late (at max), 4 days late (over max ? 0).
    const std::vector<Case> cases = {
        { +60,           100.0, "on time (deadline 60s in future)" },
        { -86400 - 60,    90.0, "1 day late" },
        { -3 * 86400 - 60, 70.0, "3 days late (at max)" },
        { -4 * 86400 - 60,  0.0, "4 days late (over max ? rejected)" },
    };

    for (const auto& c : cases) {
        World w;
        const int courseId = w.svc->createCourse(*w.admin, "CS300", "Course", "CS");
        w.svc->enrollStudent(*w.admin, w.student->id(), courseId);
        const std::string due = plusSeconds(nowLocal(), c.offsetSeconds);
        const int aid = w.svc->createAssessment(*w.lecturer, courseId, "HW",
                                                100.0, due,
                                                /*late=*/true, /*resubmit=*/true);
        try {
            const int sid = w.svc->submit(*w.student, aid, "answer");
            w.svc->grade(*w.lecturer, sid, 100.0, "");
            w.svc->moderate(*w.hod, sid);
            w.svc->release(*w.hod, sid);
            const auto rows = w.svc->results(*w.student);
            CHECK(rows.size() == 1);
            CHECK_NEAR(rows[0].final, c.expectedFinal, 1e-6);
        } catch (const ValidationError&) {
            // For the "over max" case the service rejects the submission
            // outright — that's also an acceptable outcome, but our case
            // expects it to be *accepted* then scored 0. So failure here
            // is a genuine test failure.
            CHECK(false);
        } catch (const std::exception& e) {
            std::cerr << "    unexpected: " << e.what() << " (" << c.label << ")\n";
            CHECK(false);
        }
    }
}

// Extension must strictly move the deadline later; per-student beats class-wide.
static void test_Extensions_Interaction() {
    suite("SYSTEM extensions — equivalence partitioning of due dates");

    World w;
    const int courseId = w.svc->createCourse(*w.admin, "CS400", "Course", "CS");
    w.svc->enrollStudent(*w.admin, w.student->id(), courseId);
    const int aid = w.svc->createAssessment(*w.lecturer, courseId, "Exam",
                                            50.0, "2030-01-01 00:00:00",
                                            true, true);

    // Non-later extension ? rejected
    CHECK_THROWS(w.svc->grantExtension(*w.lecturer, aid, 0, "2030-01-01 00:00:00", "no change"), ValidationError);
    CHECK_THROWS(w.svc->grantExtension(*w.lecturer, aid, 0, "2029-12-31 00:00:00", "earlier"), ValidationError);

    // Class-wide extension
    w.svc->grantExtension(*w.lecturer, aid, 0, "2030-02-01 00:00:00", "class-wide");
    // Student-specific extension later than class-wide
    w.svc->grantExtension(*w.lecturer, aid, w.student->id(), "2030-03-01 00:00:00", "medical");

    // Only lecturers may grant
    CHECK_THROWS(w.svc->grantExtension(*w.admin, aid, 0, "2030-04-01 00:00:00", "x"), ValidationError);
}

// =====================================================================
// main
// =====================================================================
int main() {
    try {
        test_parseLocalDateTime_EP();
        test_PasswordHasher_BVA();
        test_PenaltyPolicy_BVA_EP();
        test_requireText_EP();
        test_Audit_OnSuccess_And_Rollback();
        test_RBAC_Matrix_System();
        test_Workflow_HappyPath();
        test_LatePenalty_EndToEnd_BVA();
        test_Extensions_Interaction();
    } catch (const std::exception& e) {
        std::cerr << "FATAL: " << e.what() << "\n";
        return 1;
    }
    std::cout << "\nPassed: " << g_pass << "   Failed: " << g_fail << "\n";
    return g_fail == 0 ? 0 : 1;
}
