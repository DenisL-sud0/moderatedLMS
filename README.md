# Moderated Offline LMS — C++17

A runnable, offline-first console baseline for the moderated LMS design. It persists accounts, courses, enrolments, assessments, extensions, submissions, marks and audit events in SQLite.

## Dependencies

- CMake 3.16 or newer
- C++17 compiler (GCC, Clang or MSVC)
- SQLite3 development package
- OpenSSL Crypto development package

## Build and run

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
./build/offline_lms
```

On Windows, run `build\\Release\\offline_lms.exe` with a multi-configuration generator, or `build\\offline_lms.exe` with a single-configuration generator.

The application creates `offline_lms.sqlite3` in its current working directory. Keep that file in a protected location and include it in the school's backup routine.

## First login

When the database has no accounts, the program creates:

- Username: `admin`
- Temporary password: `ChangeMe!123`

Change it immediately using menu option **11**. All users can change their own password through that option. Do not deploy the default credential.

## Roles and design patterns

- **Inheritance and polymorphism:** abstract `User`, with `Administrator`, `Lecturer`, `HeadOfDepartment` and `Student` subclasses. Service methods authorize through role capabilities rather than repeated role-string comparisons.
- **Factory:** `UserFactory` creates the appropriate derived user after authentication.
- **Repository / data-access layer:** `UserRepository`, `CourseRepository`, `AssessmentRepository`, `SubmissionRepository` and `AuditRepository` encapsulate SQL. Application/service code does not issue SQL directly. All data values are bound to prepared statements; SQL strings are fixed statements.
- **Strategy:** `IAssessmentPolicy` and `StandardLatePenaltyPolicy` encapsulate the mark calculation.
- **Observer:** `EventPublisher` notifies `AuditObserver`, which writes events through `AuditRepository`. Audit writes and the corresponding state changes are wrapped in SQLite transactions.
- **Layered architecture:** console presentation → `LMSService` application logic → repositories/data-access → SQLite.

## Assessment rules implemented

- **Effective deadline:** original deadline unless a lecturer has authorised an extension. An individual extension takes precedence over a class-wide extension. An extension must move the applicable deadline later.
- **Late window:** late work is accepted only when enabled, and only up to three late days after the effective deadline. Beyond that, the submission is rejected (not stored as a zero-mark attempt).
- **Penalty:** 10% of the assessment's *available marks* is deducted for each late day. For a 100-mark assessment, a raw mark of 80 submitted two late days after the deadline becomes 60. The result is clamped between zero and the available marks.
- **Definition of a late day:** each started 24-hour period after the deadline counts as one day. For example, one second late is day 1; 24 hours and one second late is day 2.
- **Resubmission:** when enabled, each resubmission creates a new attempt with an incremented attempt number and `previous_submission_id`. Earlier attempts are retained. The late window and effective deadline apply to every attempt.
- **Moderation:** lecturer grading changes status to `GRADED`; HoD approval changes it to `APPROVED`; HoD release changes it to `RELEASED`. Students can query only their released marks.
- **Audit:** records user/course/assessment creation, enrolment, submissions, extensions, password changes, mark changes (old and new mark), moderation and release.

Deadlines are interpreted in the local timezone of the computer running the application and use `YYYY-MM-DD HH:MM:SS`. Invalid calendar dates are rejected.

## Password storage

Passwords are never stored as plaintext. OpenSSL's PBKDF2-HMAC-SHA256 implementation derives a 256-bit hash using a cryptographically random 16-byte per-user salt and 600,000 iterations. This is a recognised password-based key derivation function. If the deployment standard mandates Argon2id specifically, replace this implementation with a maintained Argon2 library and store its algorithm parameters with each credential.

## Current scope and limitations

This is a working academic implementation, not yet a complete production school deployment:

- Submission payloads are currently stored as text in SQLite. Binary file attachments, filesystem/object storage, upload scanning, size limits and checksums are not implemented.
- The console is a single-process interface. SQLite WAL and a busy timeout are enabled, but a LAN client/server service and tested 50-user concurrency are not included.
- Department-level scoping for HoD/lecturer accounts, full course/lesson/question management, and richer enrollment administration should be added before deployment.
- The date policy uses the host computer's local timezone; a school-wide timezone configuration and daylight-saving edge-case tests should be added.
- Add automated unit/integration tests, backup/restore, account lockout, secure non-echoing password entry, password reset administration and deployment-specific security review before production use.
