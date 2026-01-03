# database.py
import mysql.connector
from werkzeug.security import generate_password_hash

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "Tanisha@1105",
    "database": "hiring_platform"
}

def get_connection():
    return mysql.connector.connect(**DB_CONFIG)

def create_tables():
    db = get_connection()
    cursor = db.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS admins (
        id VARCHAR(20) PRIMARY KEY, 
        name VARCHAR(100),
        email VARCHAR(120) UNIQUE,
        password VARCHAR(255),
        profile_completed BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS candidates (
        id VARCHAR(20) PRIMARY KEY,
        name VARCHAR(100),
        email VARCHAR(120) UNIQUE,
        password VARCHAR(255),
        profile_completed BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        -- Combined Profile Columns for Single Table approach
        c_first_name VARCHAR(100), 
        c_resume_file VARCHAR(255)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS recruiters (
        id VARCHAR(20) PRIMARY KEY,
        name VARCHAR(100),
        email VARCHAR(120) UNIQUE,
        password VARCHAR(255),
        profile_completed BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        r_company_name VARCHAR(150), 
        r_website VARCHAR(255)
    )
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS mentors (
        id VARCHAR(20) PRIMARY KEY,
        name VARCHAR(100),
        email VARCHAR(120) UNIQUE,
        password VARCHAR(255),
        profile_completed BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        m_expertise VARCHAR(255), 
        m_verification_status VARCHAR(50) DEFAULT 'pending'
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS candidate_profiles (
        id INT AUTO_INCREMENT PRIMARY KEY,
        candidate_id VARCHAR(20) UNIQUE,
        first_name VARCHAR(100),
        last_name VARCHAR(100),
        headline VARCHAR(255),
        bio TEXT,
        education VARCHAR(255),
        skills TEXT,
        experience TEXT,
        resume_file VARCHAR(255),
        photo_file VARCHAR(255),
        
        -- Personal & Availability
        current_location VARCHAR(255),
        preferred_work_mode VARCHAR(50),
        open_to_relocation VARCHAR(10),
        job_type_preference VARCHAR(100),
        notice_period VARCHAR(50),
        availability_date DATE,
        
        -- Career & Role Preferences
        preferred_job_role VARCHAR(255),
        career_objective TEXT,
        interested_domains TEXT,
        
        -- Skills & Technical Details
        primary_skills TEXT,
        secondary_skills TEXT,
        skill_proficiency VARCHAR(50),
        frameworks_libraries TEXT,
        `databases` TEXT,
        tools_technologies TEXT,
        cloud_platforms TEXT,
        
        -- Projects (stored as JSON or delimited text)
        projects TEXT,
        
        -- Experience (stored as JSON or delimited text)
        work_experience TEXT,
        
        -- Education Structured
        degree VARCHAR(255),
        specialization VARCHAR(255),
        college_university VARCHAR(255),
        education_start_year INT,
        education_end_year INT,
        cgpa_percentage VARCHAR(50),
        
        -- Portfolio & Social Links
        github_url VARCHAR(255),
        linkedin_url VARCHAR(255),
        portfolio_url VARCHAR(255),
        coding_platforms TEXT,
        
        -- Certifications
        certifications TEXT,
        
        -- Soft Skills & Languages
        soft_skills TEXT,
        languages_known TEXT,
        language_proficiency TEXT,
        
        -- Mentorship Preferences
        open_to_mentorship VARCHAR(10),
        preferred_mentor_expertise TEXT,
        willing_ai_assessments VARCHAR(10),
        profile_visibility VARCHAR(20) DEFAULT 'Public',
        
        profile_completed BOOLEAN DEFAULT 0,
        profile_percent INT DEFAULT 0,
        FOREIGN KEY (candidate_id) REFERENCES candidates(id)
    );
    """)
    
    # Add new columns if they don't exist (for existing tables)
    try:
        cursor.execute("ALTER TABLE candidate_profiles ADD COLUMN photo_file VARCHAR(255)")
    except Exception:
        pass
    
    new_columns = [
        "ADD COLUMN current_location VARCHAR(255)",
        "ADD COLUMN preferred_work_mode VARCHAR(50)",
        "ADD COLUMN open_to_relocation VARCHAR(10)",
        "ADD COLUMN job_type_preference VARCHAR(100)",
        "ADD COLUMN notice_period VARCHAR(50)",
        "ADD COLUMN availability_date DATE",
        "ADD COLUMN preferred_job_role VARCHAR(255)",
        "ADD COLUMN career_objective TEXT",
        "ADD COLUMN interested_domains TEXT",
        "ADD COLUMN primary_skills TEXT",
        "ADD COLUMN secondary_skills TEXT",
        "ADD COLUMN skill_proficiency VARCHAR(50)",
        "ADD COLUMN frameworks_libraries TEXT",
        "ADD COLUMN `databases` TEXT",
        "ADD COLUMN tools_technologies TEXT",
        "ADD COLUMN cloud_platforms TEXT",
        "ADD COLUMN projects TEXT",
        "ADD COLUMN work_experience TEXT",
        "ADD COLUMN degree VARCHAR(255)",
        "ADD COLUMN specialization VARCHAR(255)",
        "ADD COLUMN college_university VARCHAR(255)",
        "ADD COLUMN education_start_year INT",
        "ADD COLUMN education_end_year INT",
        "ADD COLUMN cgpa_percentage VARCHAR(50)",
        "ADD COLUMN github_url VARCHAR(255)",
        "ADD COLUMN linkedin_url VARCHAR(255)",
        "ADD COLUMN portfolio_url VARCHAR(255)",
        "ADD COLUMN coding_platforms TEXT",
        "ADD COLUMN certifications TEXT",
        "ADD COLUMN soft_skills TEXT",
        "ADD COLUMN languages_known TEXT",
        "ADD COLUMN language_proficiency TEXT",
        "ADD COLUMN open_to_mentorship VARCHAR(10)",
        "ADD COLUMN preferred_mentor_expertise TEXT",
        "ADD COLUMN willing_ai_assessments VARCHAR(10)",
        "ADD COLUMN profile_visibility VARCHAR(20) DEFAULT 'Public'"
    ]
    
    for col_def in new_columns:
        try:
            cursor.execute(f"ALTER TABLE candidate_profiles {col_def}")
        except Exception:
            pass

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS mentor_profiles (
        id INT AUTO_INCREMENT PRIMARY KEY,
        mentor_id VARCHAR(20) UNIQUE,
        expertise VARCHAR(255),
        mentoring_areas TEXT,
        mode VARCHAR(50),
        experience INT,
        designation VARCHAR(100),
        company VARCHAR(150),
        linkedin VARCHAR(255),
        session_duration VARCHAR(50),
        max_candidates INT,
        communication VARCHAR(50),
        bio TEXT,
        available_days VARCHAR(50),
        time_slot VARCHAR(50),
        verification_type VARCHAR(50),
        verification_file VARCHAR(255),
        verification_status ENUM('pending','approved','rejected') DEFAULT 'pending',
        profile_percent INT DEFAULT 0,
        FOREIGN KEY (mentor_id) REFERENCES mentors(id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS mentor_meetings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        mentor_id VARCHAR(20) NOT NULL,
        candidate_id VARCHAR(20) NOT NULL,
        mode VARCHAR(50),
        meeting_date DATE,
        meeting_time TIME,
        meeting_link VARCHAR(255),
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_meeting_pair (mentor_id, candidate_id)
    )
    """)
    # Recruiter profiles: ensure verification_status exists for admin approvals
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS recruiter_profiles (
        id INT AUTO_INCREMENT PRIMARY KEY,
        recruiter_id VARCHAR(20),
        full_name VARCHAR(100),
        designation VARCHAR(100),
        company_name VARCHAR(150),
        phone VARCHAR(20),
        website VARCHAR(255),
        company_doc VARCHAR(255),
        auth_doc VARCHAR(255),
        linkedin VARCHAR(255),
        company_type VARCHAR(100),
        company_size VARCHAR(50),
        industry VARCHAR(100),
        address VARCHAR(255),
        logo_file VARCHAR(255),
        roles TEXT,
        experience_levels TEXT,
        job_types TEXT,
        profile_percent INT DEFAULT 0,
        verification_status ENUM('pending','approved','rejected') DEFAULT 'pending',
        FOREIGN KEY (recruiter_id) REFERENCES recruiters(id)
    )
    """)

    # Backfill missing columns for existing databases (safe no-op if present)
    try:
        cursor.execute("ALTER TABLE recruiter_profiles ADD COLUMN verification_status ENUM('pending','approved','rejected') DEFAULT 'pending'")
    except Exception:
        pass
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS mentorship_requests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        candidate_id VARCHAR(20) NOT NULL,
        mentor_id VARCHAR(20) NOT NULL,
        request_message TEXT,
        mentor_feedback TEXT,
        status ENUM('Pending','Accepted','Rejected','Completed') DEFAULT 'Pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (candidate_id) REFERENCES candidates(id),
        FOREIGN KEY (mentor_id) REFERENCES mentors(id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS notifications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        receiver_role ENUM('admin','candidate','recruiter','mentor'),
        receiver_id INT,
        message TEXT,
        is_read BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS jobs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        recruiter_id VARCHAR(20),
        title VARCHAR(150),
        department VARCHAR(100),
        location VARCHAR(150),
        job_type VARCHAR(50),
        employment_mode VARCHAR(50),
        salary_min INT,
        salary_max INT,
        min_experience INT,
        max_experience INT,
        education VARCHAR(150),
        openings INT,
        deadline DATE,
        description TEXT,
        skills TEXT,
        interview_mode VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (recruiter_id) REFERENCES recruiters(id) ON DELETE CASCADE
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS applications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        candidate_id VARCHAR(20),
        job_id INT,
        status ENUM('Applied','Shortlisted','Interview','Selected','Rejected') DEFAULT 'Applied',
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (candidate_id) REFERENCES candidates(id),
        FOREIGN KEY (job_id) REFERENCES jobs(id)
    )
    """)
    cursor.execute("""
     CREATE TABLE IF NOT EXISTS feedback (
        id INT AUTO_INCREMENT PRIMARY KEY,
        from_role ENUM('admin','candidate','recruiter','mentor'),
        from_id INT,
        to_role ENUM('admin','candidate','recruiter','mentor'),
        to_id INT,
        rating INT CHECK (rating BETWEEN 1 AND 5),
        comment TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    # Default Admin
    admin_email = "admin@hirehub.com"
    admin_password = generate_password_hash("Admin@123")

    cursor.execute("SELECT id FROM admins WHERE email=%s", (admin_email,))
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO admins (id,name,email,password,profile_completed) VALUES (%s,%s,%s,%s,%s)",
            ("ADMN-1001", "Super Admin", admin_email, admin_password, 1)
        )

    db.commit()
    cursor.close()
    db.close()
    print("Database setup completed successfully")

if __name__ == "__main__":
    create_tables()
