from database import get_connection

db = get_connection()
cursor = db.cursor(dictionary=True)

# Get all candidates
cursor.execute("SELECT id, name FROM candidates LIMIT 5")
candidates = cursor.fetchall()

print("=" * 80)
print("CHECKING CANDIDATE PROFILES")
print("=" * 80)

for cand in candidates:
    print(f"\nCandidate: {cand['id']} - {cand['name']}")
    
    cursor.execute("SELECT * FROM candidate_profiles WHERE candidate_id = %s", (cand['id'],))
    profile = cursor.fetchone()
    
    if profile:
        print(f"  Primary Skills: {profile.get('primary_skills')}")
        print(f"  Secondary Skills: {profile.get('secondary_skills')}")
        print(f"  Frameworks: {profile.get('frameworks_libraries')}")
        print(f"  Databases: {profile.get('databases')}")
        print(f"  Cloud Platforms: {profile.get('cloud_platforms')}")
        print(f"  Tools: {profile.get('tools_technologies')}")
    else:
        print("  No profile found!")

cursor.close()
db.close()

print("\n" + "=" * 80)
print("CHECKING TEST DATA")
print("=" * 80)

db = get_connection()
cursor = db.cursor(dictionary=True)

cursor.execute("SELECT * FROM ai_tests ORDER BY id DESC LIMIT 3")
tests = cursor.fetchall()

for test in tests:
    print(f"\nTest ID: {test['id']} (Candidate: {test['candidate_id']})")
    print(f"  Skills Tested: {test.get('skills_tested')}")
    print(f"  Status: {test['status']}")
    
    cursor.execute("SELECT COUNT(*) as count FROM ai_test_questions WHERE test_id = %s", (test['id'],))
    count = cursor.fetchone()
    print(f"  Questions: {count['count']}")
    
    if count['count'] > 0:
        cursor.execute("SELECT question_text FROM ai_test_questions WHERE test_id = %s LIMIT 3", (test['id'],))
        questions = cursor.fetchall()
        for q in questions:
            print(f"    - {q['question_text'][:80]}...")

cursor.close()
db.close()
