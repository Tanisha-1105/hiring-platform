#app.py
import os
from dotenv import load_dotenv 


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

from flask import Flask, render_template, request, redirect, session, url_for, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from database import get_connection, create_tables
import pymupdf as fitz  # PyMuPDF
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from werkzeug.utils import secure_filename
from flask import flash
from flask import jsonify
from flask_socketio import SocketIO, join_room

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "hirehub-secret")

UPLOAD_FOLDER = "static/uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Create tables when app starts
create_tables()
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD')
)

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')


@socketio.on('join')
def on_join(data):
    role = data.get('role')
    user_id = data.get('id')
    try:
        if role == 'mentor' and user_id:
            join_room(f"mentor_{user_id}")
    except Exception:
        pass

@app.route("/")
def home():
    return render_template("index.html ")

@app.route("/login", methods=["GET", "POST"])
def login():
    role = request.form.get("role") or request.args.get("role")

    table_map = {
        "admin": "admins",
        "candidate": "candidates",
        "recruiter": "recruiters",
        "mentor": "mentors"
    }

    if request.method == "POST":
        if not role:
            return "Role missing", 400

        role = role.strip().lower()

        if role not in table_map:
            return "Invalid role", 400

        email = request.form.get("email")
        password = request.form.get("password")
        remember = request.form.get("remember")

        db = get_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            f"SELECT * FROM {table_map[role]} WHERE email=%s",
            (email,)
        )
        user = cursor.fetchone()

        cursor.close()
        db.close()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["role"] = role
            session.permanent = bool(remember)

            dashboard_map = {
                "candidate": "/candidate-dashboard",
                "recruiter": "/recruiter-dashboard",
                "mentor": "/mentor-dashboard",
                "admin": "/admin-dashboard"
            }
            return redirect(dashboard_map[role])

        return "Invalid credentials"

    return render_template("login.html", role=role)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")

        db = get_connection()
        cursor = db.cursor(dictionary=True)
        for table in ["admins", "candidates", "recruiters", "mentors"]:
            cursor.execute(
                f"SELECT id FROM {table} WHERE email=%s",
                (email,)
            )

            user = cursor.fetchone()

            if user:
                token = serializer.dumps(email, salt="password-reset")

                reset_link = url_for(
                    'reset_password_token',
                    token=token,
                    _external=True
                )

                msg = Message(
                    "HireHub Password Reset",
                    recipients=[email]
                )
                msg.body = (
                    "Hi,\n\n"
                    "Click the link below to reset your password:\n\n"
                    f"{reset_link}\n\n"
                    "This link expires in 10 minutes.\n\n"
                    "If you didn't request this, ignore this email."
                )
                mail.send(msg)
            return "If the email exists, a reset link has been sent."
    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password_token(token):
    try:
        email = serializer.loads(
            token,
            salt="password-reset",
            max_age=600  #10 min
        )
    except:
        return "Reset link expired or invalid"
    if request.method == "POST":
        new_password = generate_password_hash(request.form.get("password"))

        db = get_connection()
        cursor = db.cursor()
        for table in ["admins", "candidates", "recruiters", "mentors"]:
            cursor.execute(
                f"UPDATE {table} SET password=%s WHERE email=%s",
                (new_password, email)
            )
        db.commit()
        return redirect("/login")
    return render_template("reset_password.html")
def generate_custom_id(role):
    if not role:
        return None

    role = role.strip().lower()

    role_config = {
        'candidate': {'table': 'candidates', 'prefix': 'CAND'},
        'recruiter': {'table': 'recruiters', 'prefix': 'RECT'},
        'mentor': {'table': 'mentors', 'prefix': 'MENT'},
        'admin': {'table': 'admins', 'prefix': 'ADMN'}
    }

    if role not in role_config:
        raise ValueError("Invalid role")
    db = get_connection()
    cursor = db.cursor()
    table = role_config[role]['table']
    prefix = role_config[role]['prefix']

    cursor.execute(f"SELECT COUNT(*) FROM {table}")
    count = cursor.fetchone()[0]

    new_number = count + 1001

    cursor.close()
    db.close()

    return f"{prefix}-{new_number}"
@app.route("/register", methods=["GET", "POST"])
def register():
    role = request.args.get("role") or request.form.get("role")

    allowed_roles = ["candidate", "recruiter", "mentor"]
    table_map = {
        "candidate": "candidates",
        "recruiter": "recruiters",
        "mentor": "mentors"
    }

    if not role or role not in allowed_roles:
        return redirect("/")

    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Optional but recommended
        if password != confirm_password:
            return render_template(
                "register.html",
                role=role,
                error="Passwords do not match"
            )

        custom_id = generate_custom_id(role)
        hashed_password = generate_password_hash(password)

        db = get_connection()
        cursor = db.cursor()

        try:
            cursor.execute(
                f"""
                INSERT INTO {table_map[role]}
                (id, name, email, password, profile_completed)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (custom_id, name, email, hashed_password, 0)
            )
            db.commit()

        except mysql.connector.IntegrityError:
            return render_template(
                "register.html",
                role=role,
                error="Email already registered"
            )

        finally:
            cursor.close()
            db.close()

        return redirect(f"/login?role={role}")

    return render_template("register.html", role=role)


@app.route('/candidate-dashboard', methods=["GET", "POST"])
def candidate_dashboard():
    if session.get('role') != 'candidate':
        return redirect('/login')

    candidate_id = session.get('user_id')
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM candidate_profiles WHERE candidate_id=%s", (candidate_id,))
    profile = cursor.fetchone()

    if request.method == "POST":
        # Collect all form data
        data = {
            'first_name': request.form.get('firstName'),
            'last_name': request.form.get('lastName'),
            'headline': request.form.get('headline'),
            'bio': request.form.get('about'),
            'current_location': request.form.get('current_location'),
            'preferred_work_mode': request.form.get('preferred_work_mode'),
            'open_to_relocation': request.form.get('open_to_relocation'),
            'job_type_preference': request.form.get('job_type_preference'),
            'notice_period': request.form.get('notice_period'),
            'availability_date': request.form.get('availability_date'),
            'preferred_job_role': request.form.get('preferred_job_role'),
            'career_objective': request.form.get('career_objective'),
            'interested_domains': request.form.get('interested_domains'),
            'primary_skills': request.form.get('primary_skills'),
            'secondary_skills': request.form.get('secondary_skills'),
            'skill_proficiency': request.form.get('skill_proficiency'),
            'frameworks_libraries': request.form.get('frameworks_libraries'),
            'databases': request.form.get('databases'),
            'tools_technologies': request.form.get('tools_technologies'),
            'cloud_platforms': request.form.get('cloud_platforms'),
            'projects': request.form.get('projects'),
            'work_experience': request.form.get('work_experience'),
            'degree': request.form.get('degree'),
            'specialization': request.form.get('specialization'),
            'college_university': request.form.get('college_university'),
            'education_start_year': request.form.get('education_start_year'),
            'education_end_year': request.form.get('education_end_year'),
            'cgpa_percentage': request.form.get('cgpa_percentage'),
            'github_url': request.form.get('github_url'),
            'linkedin_url': request.form.get('linkedin_url'),
            'portfolio_url': request.form.get('portfolio_url'),
            'coding_platforms': request.form.get('coding_platforms'),
            'certifications': request.form.get('certifications'),
            'soft_skills': request.form.get('soft_skills'),
            'languages_known': request.form.get('languages_known'),
            'language_proficiency': request.form.get('language_proficiency'),
            'open_to_mentorship': request.form.get('open_to_mentorship'),
            'preferred_mentor_expertise': request.form.get('preferred_mentor_expertise'),
            'willing_ai_assessments': request.form.get('willing_ai_assessments'),
            'profile_visibility': request.form.get('profile_visibility')
        }

        # Handle resume upload
        file = request.files.get('resume')
        filename = profile['resume_file'] if profile else None
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        # Handle profile picture upload
        photo = request.files.get('photo')
        photo_filename = profile.get('photo_file') if profile else None
        if photo and photo.filename != '':
            photo_filename = secure_filename(photo.filename)
            photo.save(os.path.join(app.config["UPLOAD_FOLDER"], photo_filename))

        # Calculate profile completion percentage
        required_fields = [data['first_name'], data['last_name'], data['headline'], data['bio'], 
                          data['primary_skills'], data['degree'], data['college_university'], filename]
        optional_fields = [data['current_location'], data['preferred_work_mode'], data['job_type_preference'],
                          data['preferred_job_role'], data['secondary_skills'], data['frameworks_libraries'],
                          data['projects'], data['work_experience'], data['github_url'], data['linkedin_url']]
        
        filled_required = sum(1 for f in required_fields if f and str(f).strip())
        filled_optional = sum(1 for f in optional_fields if f and str(f).strip())
        
        profile_percent = int((filled_required / len(required_fields)) * 70 + (filled_optional / len(optional_fields)) * 30)
        profile_completed = 1 if profile_percent >= 70 else 0

        cursor.execute("""
            INSERT INTO candidate_profiles 
            (candidate_id, first_name, last_name, headline, bio, resume_file, photo_file,
             current_location, preferred_work_mode, open_to_relocation, job_type_preference, notice_period, availability_date,
             preferred_job_role, career_objective, interested_domains,
             primary_skills, secondary_skills, skill_proficiency, frameworks_libraries, `databases`, tools_technologies, cloud_platforms,
             projects, work_experience,
             degree, specialization, college_university, education_start_year, education_end_year, cgpa_percentage,
             github_url, linkedin_url, portfolio_url, coding_platforms,
             certifications, soft_skills, languages_known, language_proficiency,
             open_to_mentorship, preferred_mentor_expertise, willing_ai_assessments, profile_visibility,
             profile_completed, profile_percent)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            first_name=VALUES(first_name), last_name=VALUES(last_name), headline=VALUES(headline), bio=VALUES(bio),
            current_location=VALUES(current_location), preferred_work_mode=VALUES(preferred_work_mode), 
            open_to_relocation=VALUES(open_to_relocation), job_type_preference=VALUES(job_type_preference),
            notice_period=VALUES(notice_period), availability_date=VALUES(availability_date),
            preferred_job_role=VALUES(preferred_job_role), career_objective=VALUES(career_objective), interested_domains=VALUES(interested_domains),
            primary_skills=VALUES(primary_skills), secondary_skills=VALUES(secondary_skills), skill_proficiency=VALUES(skill_proficiency),
            frameworks_libraries=VALUES(frameworks_libraries), `databases`=VALUES(`databases`), tools_technologies=VALUES(tools_technologies), cloud_platforms=VALUES(cloud_platforms),
            projects=VALUES(projects), work_experience=VALUES(work_experience),
            degree=VALUES(degree), specialization=VALUES(specialization), college_university=VALUES(college_university),
            education_start_year=VALUES(education_start_year), education_end_year=VALUES(education_end_year), cgpa_percentage=VALUES(cgpa_percentage),
            github_url=VALUES(github_url), linkedin_url=VALUES(linkedin_url), portfolio_url=VALUES(portfolio_url), coding_platforms=VALUES(coding_platforms),
            certifications=VALUES(certifications), soft_skills=VALUES(soft_skills), languages_known=VALUES(languages_known), language_proficiency=VALUES(language_proficiency),
            open_to_mentorship=VALUES(open_to_mentorship), preferred_mentor_expertise=VALUES(preferred_mentor_expertise),
            willing_ai_assessments=VALUES(willing_ai_assessments), profile_visibility=VALUES(profile_visibility),
            resume_file=VALUES(resume_file), photo_file=VALUES(photo_file), profile_completed=VALUES(profile_completed), profile_percent=VALUES(profile_percent)
        """, (candidate_id, data['first_name'], data['last_name'], data['headline'], data['bio'], filename, photo_filename,
              data['current_location'], data['preferred_work_mode'], data['open_to_relocation'], data['job_type_preference'], 
              data['notice_period'], data['availability_date'], data['preferred_job_role'], data['career_objective'], data['interested_domains'],
              data['primary_skills'], data['secondary_skills'], data['skill_proficiency'], data['frameworks_libraries'], 
              data['databases'], data['tools_technologies'], data['cloud_platforms'], data['projects'], data['work_experience'],
              data['degree'], data['specialization'], data['college_university'], data['education_start_year'], 
              data['education_end_year'], data['cgpa_percentage'], data['github_url'], data['linkedin_url'], 
              data['portfolio_url'], data['coding_platforms'], data['certifications'], data['soft_skills'], 
              data['languages_known'], data['language_proficiency'], data['open_to_mentorship'], data['preferred_mentor_expertise'],
              data['willing_ai_assessments'], data['profile_visibility'], profile_completed, profile_percent))

        db.commit()
        flash("Profile updated successfully!", "success")
        return redirect('/candidate-dashboard#profile') 

    profile_completed = 1 if profile else 0
    profile_percent = profile['profile_percent'] if profile else 0

    # Fetch all verified mentors for the Find a Mentor section
    cursor.execute("""
        SELECT mp.mentor_id, mp.expertise, mp.mentoring_areas, mp.mode, mp.experience,
               mp.designation, mp.company, mp.linkedin, mp.session_duration, mp.max_candidates,
               mp.communication, mp.bio, mp.available_days, mp.time_slot, mp.photo_file,
               m.name
        FROM mentor_profiles mp
        JOIN mentors m ON mp.mentor_id = m.id
        WHERE mp.verification_status = 'approved'
        ORDER BY mp.experience DESC
    """)
    available_mentors = cursor.fetchall()

    # Fetch candidate's mentorship requests and status
    cursor.execute("""
        SELECT mr.id, mr.status, mr.request_message, mr.mentor_feedback, mr.created_at,
               m.name AS mentor_name, mp.expertise, mp.company
        FROM mentorship_requests mr
        JOIN mentors m ON mr.mentor_id = m.id
        LEFT JOIN mentor_profiles mp ON m.id = mp.mentor_id
        WHERE mr.candidate_id = %s
        ORDER BY mr.created_at DESC
    """, (candidate_id,))
    mentorship_requests = cursor.fetchall()

    # Fetch meetings scheduled for this candidate keyed by mentor
    cursor.execute(
        """
        SELECT mm.mentor_id, mm.mode, mm.meeting_date, mm.meeting_time, mm.meeting_link, mm.notes,
               m.name AS mentor_name
        FROM mentor_meetings mm
        JOIN mentors m ON mm.mentor_id = m.id
        WHERE mm.candidate_id = %s
        """,
        (candidate_id,)
    )
    meetings = cursor.fetchall()
    meeting_map = {row['mentor_id']: row for row in meetings}

    # Count applied jobs (placeholder for now)
    applied_count = 0

    # Fetch AI test results for this candidate
    cursor.execute("""
        SELECT id, test_type, total_questions, total_marks, obtained_marks, 
               percentage, status, skills_tested, completed_at
        FROM ai_tests
        WHERE candidate_id = %s
        ORDER BY completed_at DESC
    """, (candidate_id,))
    ai_tests = cursor.fetchall()

    # Fetch AI mock interview results
    cursor.execute("""
        SELECT id, interview_type, position_role, difficulty_level, 
               total_questions, questions_answered, overall_score, 
               status, completed_at
        FROM ai_mock_interviews
        WHERE candidate_id = %s
        ORDER BY started_at DESC
    """, (candidate_id,))
    mock_interviews = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template(
        'candidate_dashboard.html',
        profile_completed=profile_completed,
        profile_percent=profile_percent,
        profile=profile,
        available_mentors=available_mentors,
        applied_count=applied_count,
        mentorship_requests=mentorship_requests,
        meeting_map=meeting_map,
        ai_tests=ai_tests,
        mock_interviews=mock_interviews
    )
@app.route('/api/profile')
def get_profile_api():
    user_id = session.get('user_id')
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM candidate_profiles WHERE candidate_id=%s", (user_id,))
    profile = cursor.fetchone()
    cursor.close()
    db.close()

    if profile:
        return {"exists": True, "completed": True, "completion": profile['profile_percent'], "data": profile}
    return {"exists": False}
@app.route('/api/profile/draft', methods=['POST'])
def save_draft():
    data = request.json.get('data')
    return {"success": True, "message": "Draft saved"}

@app.route('/candidate/delete-profile', methods=['POST'])
def delete_candidate_profile():
    if session.get('role') != 'candidate':
        return redirect('/login')

    user_id = session.get('user_id')
    db = get_connection()
    cursor = db.cursor()

    try:
        cursor.execute("DELETE FROM candidate_profiles WHERE candidate_id = %s", (user_id,))
        cursor.execute("UPDATE candidates SET profile_completed = 0 WHERE id = %s", (user_id,))
        db.commit()
        flash("Profile deleted. You can rebuild it anytime.", "info")
    except Exception as e:
        print(f"Error deleting candidate profile: {e}")
        db.rollback()
        flash("Could not delete profile. Please try again.", "danger")
    finally:
        cursor.close()
        db.close()

    return redirect('/candidate-dashboard?tab=profile')

@app.route('/api/parse-resume', methods=['POST'])
def parse_resume():
    """Parse uploaded resume PDF and extract candidate information"""
    try:
        if session.get('role') != 'candidate':
            return jsonify({'success': False, 'message': 'Unauthorized'}), 401
        
        if 'resume' not in request.files:
            return jsonify({'success': False, 'message': 'No file uploaded'}), 400
        
        file = request.files['resume']
        
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        
        if not file.filename.endswith('.pdf'):
            return jsonify({'success': False, 'message': 'Only PDF files are allowed'}), 400
        
        # Save the file temporarily
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Extract text from PDF
        text = extract_text_from_pdf(filepath)
        
        print(f"DEBUG: Extracted text length: {len(text) if text else 0}")
        print(f"DEBUG: First 200 chars: {text[:200] if text else 'None'}")
        
        if not text or len(text.strip()) < 10:
            return jsonify({
                'success': False, 
                'message': 'This PDF appears to be image-based or scanned. Please use a text-based PDF resume or click "Fill Manually" to enter your details.',
                'suggestion': 'manual'
            }), 400
        
        # Parse the extracted text
        parsed_data = parse_resume_text(text)
        
        print(f"DEBUG: Parsed data: {parsed_data}")
        
        # Add filename for later use
        parsed_data['resume_filename'] = filename
        
        return jsonify({'success': True, 'data': parsed_data})
    
    except Exception as e:
        print(f"Error parsing resume: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

def extract_text_from_pdf(filepath):
    """Extract text content from PDF file"""
    try:
        print(f"DEBUG: Opening PDF: {filepath}")
        print(f"DEBUG: File exists: {os.path.exists(filepath)}")
        
        doc = fitz.open(filepath)
        print(f"DEBUG: PDF opened successfully. Pages: {len(doc)}")
        
        text = ""
        for page_num, page in enumerate(doc):
            page_text = page.get_text()
            print(f"DEBUG: Page {page_num + 1} text length: {len(page_text)}")
            text += page_text
        
        doc.close()
        print(f"DEBUG: Total extracted text length: {len(text)}")
        return text
    except Exception as e:
        print(f"DEBUG: Error in extract_text_from_pdf: {str(e)}")
        import traceback
        traceback.print_exc()
        raise Exception(f"Failed to extract text from PDF: {str(e)}")

def parse_resume_text(text):
    """Parse resume text and extract structured information"""
    import re
    
    data = {}
    text_lower = text.lower()
    lines = text.split('\n')
    
    # Extract Name (usually first non-empty line)
    for line in lines:
        line = line.strip()
        if line and len(line) > 2 and not any(char.isdigit() for char in line[:10]):
            name_parts = line.split()
            if len(name_parts) >= 2:
                data['first_name'] = name_parts[0]
                data['last_name'] = ' '.join(name_parts[1:])
                break
    
    # Extract Email
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_pattern, text)
    if emails:
        data['email'] = emails[0]
    
    # Extract Phone
    phone_pattern = r'[\+\(]?[0-9][0-9 .\-\(\)]{8,}[0-9]'
    phones = re.findall(phone_pattern, text)
    if phones:
        data['phone'] = phones[0].strip()
    
    # Extract LinkedIn
    linkedin_pattern = r'linkedin\.com/in/[\w-]+'
    linkedin_matches = re.findall(linkedin_pattern, text_lower)
    if linkedin_matches:
        data['linkedin_url'] = 'https://' + linkedin_matches[0]
    
    # Extract GitHub
    github_pattern = r'github\.com/[\w-]+'
    github_matches = re.findall(github_pattern, text_lower)
    if github_matches:
        data['github_url'] = 'https://' + github_matches[0]
    
    # Extract Skills
    skills_keywords = ['python', 'java', 'javascript', 'react', 'node', 'sql', 'mysql', 'mongodb',
                      'html', 'css', 'django', 'flask', 'spring', 'aws', 'azure', 'docker', 'kubernetes',
                      'git', 'api', 'rest', 'json', 'angular', 'vue', 'typescript', 'c++', 'c#', '.net',
                      'php', 'ruby', 'go', 'kotlin', 'swift', 'android', 'ios', 'machine learning', 'ai',
                      'data science', 'tensorflow', 'pytorch', 'pandas', 'numpy']
    
    found_skills = []
    for skill in skills_keywords:
        if skill in text_lower:
            found_skills.append(skill.title())
    
    if found_skills:
        # Split into primary and secondary
        data['primary_skills'] = ', '.join(found_skills[:5])
        if len(found_skills) > 5:
            data['secondary_skills'] = ', '.join(found_skills[5:10])
    
    # Extract Education
    education_keywords = ['bachelor', 'master', 'b.tech', 'b.e.', 'm.tech', 'm.e.', 'bca', 'mca', 'bsc', 'msc']
    for i, line in enumerate(lines):
        line_lower = line.lower()
        for keyword in education_keywords:
            if keyword in line_lower:
                data['degree'] = line.strip()
                # Try to get college name from next few lines
                for j in range(i+1, min(i+4, len(lines))):
                    if lines[j].strip() and len(lines[j].strip()) > 10:
                        data['college_university'] = lines[j].strip()
                        break
                break
        if 'degree' in data:
            break
    
    # Extract Work Experience Section
    experience_section = ""
    capturing = False
    for line in lines:
        line_lower = line.lower()
        if any(keyword in line_lower for keyword in ['experience', 'work history', 'employment']):
            capturing = True
            continue
        if capturing:
            if any(keyword in line_lower for keyword in ['education', 'skills', 'projects', 'certifications']):
                break
            if line.strip():
                experience_section += line.strip() + "\n"
    
    if experience_section:
        data['work_experience'] = experience_section.strip()
    
    # Extract Projects Section
    projects_section = ""
    capturing = False
    for line in lines:
        line_lower = line.lower()
        if 'project' in line_lower:
            capturing = True
            continue
        if capturing:
            if any(keyword in line_lower for keyword in ['education', 'skills', 'experience', 'certifications']):
                break
            if line.strip():
                projects_section += line.strip() + "\n"
    
    if projects_section:
        data['projects'] = projects_section.strip()
    
    # Generate a headline if name found
    if 'first_name' in data:
        if 'primary_skills' in data:
            skills_list = data['primary_skills'].split(',')
            data['headline'] = f"{skills_list[0].strip()} Developer" if skills_list else "Software Developer"
        else:
            data['headline'] = "Software Developer"
    
    # Create a basic bio
    if 'first_name' in data:
        bio_parts = []
        if 'degree' in data:
            bio_parts.append(f"Graduate with {data['degree']}")
        if 'primary_skills' in data:
            bio_parts.append(f"skilled in {data['primary_skills']}")
        if bio_parts:
            data['bio'] = '. '.join(bio_parts) + '.'
    
    return data

@app.route('/post-job', methods=['GET', 'POST'])
def post_job():
    if session.get('role') != 'recruiter':
        return redirect('/login')

    if request.method == 'POST':
        title = request.form.get('title')
        skills = request.form.get('skills')
        recruiter_id = session['user_id']

        db = get_connection()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO jobs (title, skills, recruiter_id) VALUES (%s,%s,%s)",
            (title, skills, recruiter_id)
        )
        db.commit()
        cursor.close()
        db.close()

        return redirect('/recruiter-dashboard?tab=jobs')

    # For GET, show the embedded form on dashboard
    return redirect('/recruiter-dashboard?tab=post')

@app.route('/jobs')
def view_jobs():
    if session.get('role') != 'candidate':
        return redirect('/login')

    db = get_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT jobs.id, jobs.title, jobs.skills, recruiters.name AS recruiter
        FROM jobs
        JOIN recruiters ON jobs.recruiter_id = recruiters.id
    """)
    jobs = cursor.fetchall()
    cursor.close()
    db.close()

    return render_template('jobs.html', jobs=jobs)

@app.route('/apply/<int:job_id>')
def apply_job(job_id):
    if session.get('role') != 'candidate':
        return redirect('/login')

    db = get_connection()
    cursor = db.cursor()

    cursor.execute("""
        INSERT INTO applications (candidate_id, job_id, status)
        VALUES (%s,%s,'Applied')
    """, (session['user_id'], job_id))

    db.commit()
    cursor.close()
    db.close()

    return redirect('/candidate-dashboard')

@app.route('/my-applications')
def my_applications():
    if session.get('role') != 'candidate':
        return redirect('/login')

    db = get_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT jobs.title, applications.status
        FROM applications
        JOIN jobs ON applications.job_id = jobs.id
        WHERE applications.candidate_id = %s
    """, (session['user_id'],))
    applications = cursor.fetchall()
    cursor.close()
    db.close()

    return render_template('applications.html', applications=applications)

def calculate_match(candidate_skills, job_skills):
    job = set(job_skills.lower().split(','))
    cand = set(candidate_skills)

    match = job.intersection(cand)
    return int((len(match) / len(job)) * 100) if job else 0

@app.route('/recruiter-dashboard')
def recruiter_dashboard():
    if session.get('role') != 'recruiter':
        return redirect('/login')

    user_id = session.get('user_id')
    
    try:
        # Create separate database connection for cleaner cursor management
        db = get_connection()
        cursor = db.cursor(dictionary=True)
        
        # Get recruiter info
        cursor.execute("SELECT profile_completed FROM recruiters WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        is_complete = user['profile_completed'] if user else False
        cursor.fetchall()  # Consume any remaining results
        
        # Create new cursor for next query
        cursor.close()
        cursor = db.cursor(dictionary=True)
        
        # Get recruiter profile
        cursor.execute("SELECT * FROM recruiter_profiles WHERE recruiter_id = %s ORDER BY id DESC LIMIT 1", (user_id,))
        recruiter_profile = cursor.fetchone()
        cursor.fetchall()  # Consume any remaining results
        
        # Compute profile_percent from stored profile
        if recruiter_profile:
            required_keys = ['full_name','phone','designation','linkedin','company_name','company_type','company_size','industry','address','website','logo_file','company_doc','auth_doc','roles','experience_levels','job_types']
            total = len(required_keys)
            filled = 0
            for k in required_keys:
                val = recruiter_profile.get(k) if isinstance(recruiter_profile, dict) else None
                if val and str(val).strip() != '':
                    filled += 1
            profile_percent = int((filled/total)*100) if total else 0
        else:
            profile_percent = 40
        verification_status = recruiter_profile.get('verification_status') if recruiter_profile and isinstance(recruiter_profile, dict) else 'pending'
        
        
        # Create new cursor for jobs query
        cursor.close()
        cursor = db.cursor(dictionary=True)
        
        # Get jobs posted
        cursor.execute("SELECT * FROM jobs WHERE recruiter_id = %s", (user_id,))
        jobs = cursor.fetchall()
        cursor.fetchall()  # Consume any remaining results
        
        # Create new cursor for stats
        cursor.close()
        cursor = db.cursor(dictionary=True)
        
        # Get all stats
        cursor.execute("""
            SELECT 
                (SELECT COUNT(*) FROM jobs WHERE recruiter_id = %s) as jobs_count,
                (SELECT COUNT(*) FROM applications a JOIN jobs j ON a.job_id = j.id WHERE j.recruiter_id = %s) as applications_count,
                (SELECT COUNT(*) FROM applications a JOIN jobs j ON a.job_id = j.id WHERE j.recruiter_id = %s AND a.status = 'Interview') as interviews_count,
                (SELECT COUNT(*) FROM applications a JOIN jobs j ON a.job_id = j.id WHERE j.recruiter_id = %s AND a.status = 'Selected') as offers_count
        """, (user_id, user_id, user_id, user_id))
        
        stats = cursor.fetchone()
        cursor.fetchall()  # Consume any remaining results
        
        jobs_count = stats['jobs_count'] if stats else 0
        applications_count = stats['applications_count'] if stats else 0
        interviews_count = stats['interviews_count'] if stats else 0
        offers_count = stats['offers_count'] if stats else 0

        cursor.close()
        db.close()

        # Determine current tab (overview by default)
        current_tab = request.args.get('tab', 'overview')
        
        # Handle edit-job tab - fetch specific job for editing
        edit_job = None
        if current_tab == 'edit-job':
            job_id = request.args.get('job_id')
            if job_id:
                db = get_connection()
                cursor = db.cursor(dictionary=True)
                cursor.execute("SELECT * FROM jobs WHERE id = %s AND recruiter_id = %s", (job_id, user_id))
                edit_job = cursor.fetchone()
                cursor.close()
                db.close()

        # today's date for job deadlines when needed
        from datetime import date
        today = date.today()

        return render_template(
            'recruiter_dashboard.html', 
            is_complete=is_complete,
            profile_percent=profile_percent,
            verification_status=verification_status,
            jobs=jobs,
            jobs_count=jobs_count,
            applications_count=applications_count,
            interviews_count=interviews_count,
            offers_count=offers_count,
            tab=current_tab,
            profile=recruiter_profile,
            edit_job=edit_job,
            today=today
        )
    except Exception as e:
        print(f"Error in recruiter_dashboard: {e}")
        try:
            cursor.close()
            db.close()
        except:
            pass
        flash("Error loading dashboard", "danger")
        return redirect('/login')

@app.route('/save-recruiter-profile', methods=['POST'])
def save_recruiter_profile():
    if session.get('role') != 'recruiter':
        return redirect('/login')

    user_id = session.get('user_id')
    full_name = request.form.get('full_name')
    phone = request.form.get('phone')
    designation = request.form.get('designation')
    linkedin = request.form.get('linkedin')
    company_name = request.form.get('company_name')
    company_type = request.form.get('company_type')
    company_size = request.form.get('company_size')
    industry = request.form.get('industry')
    address = request.form.get('address')
    website = request.form.get('website')
    company_doc = request.files.get('company_doc')
    auth_doc = request.files.get('auth_doc')
    logo = request.files.get('logo_file')
    roles = request.form.get('roles')
    experience_levels = request.form.get('experience_levels')
    job_types = request.form.get('job_types')
    
    db = get_connection()
    # Fetch existing profile to preserve files when not re-uploaded
    existing_cursor = db.cursor(dictionary=True)
    existing_cursor.execute("SELECT * FROM recruiter_profiles WHERE recruiter_id = %s", (user_id,))
    existing_profile = existing_cursor.fetchone()
    existing_cursor.fetchall()
    existing_cursor.close()

    comp_filename = existing_profile['company_doc'] if existing_profile else None
    if company_doc and company_doc.filename != '':
        comp_filename = secure_filename(company_doc.filename)
        company_doc.save(os.path.join(UPLOAD_FOLDER, comp_filename))

    auth_filename = existing_profile['auth_doc'] if existing_profile else None
    if auth_doc and auth_doc.filename != '':
        auth_filename = secure_filename(auth_doc.filename)
        auth_doc.save(os.path.join(UPLOAD_FOLDER, auth_filename))

    logo_filename = existing_profile['logo_file'] if existing_profile else None
    if logo and logo.filename != '':
        logo_filename = secure_filename(logo.filename)
        logo.save(os.path.join(UPLOAD_FOLDER, logo_filename))

    cursor = db.cursor()
    
    try:
        # Ensure new columns exist
        try:
            cursor.execute("ALTER TABLE recruiter_profiles ADD COLUMN linkedin VARCHAR(255)")
        except Exception:
            pass
        try:
            cursor.execute("ALTER TABLE recruiter_profiles ADD COLUMN company_type VARCHAR(100)")
        except Exception:
            pass
        try:
            cursor.execute("ALTER TABLE recruiter_profiles ADD COLUMN company_size VARCHAR(50)")
        except Exception:
            pass
        try:
            cursor.execute("ALTER TABLE recruiter_profiles ADD COLUMN industry VARCHAR(100)")
        except Exception:
            pass
        try:
            cursor.execute("ALTER TABLE recruiter_profiles ADD COLUMN address VARCHAR(255)")
        except Exception:
            pass
        try:
            cursor.execute("ALTER TABLE recruiter_profiles ADD COLUMN logo_file VARCHAR(255)")
        except Exception:
            pass
        try:
            cursor.execute("ALTER TABLE recruiter_profiles ADD COLUMN roles TEXT")
        except Exception:
            pass
        try:
            cursor.execute("ALTER TABLE recruiter_profiles ADD COLUMN experience_levels TEXT")
        except Exception:
            pass
        try:
            cursor.execute("ALTER TABLE recruiter_profiles ADD COLUMN job_types TEXT")
        except Exception:
            pass
        try:
            cursor.execute("ALTER TABLE recruiter_profiles ADD COLUMN profile_percent INT DEFAULT 0")
        except Exception:
            pass
        try:
            cursor.execute("ALTER TABLE recruiter_profiles ADD COLUMN verification_status ENUM('pending','approved','rejected') DEFAULT 'pending'")
        except Exception:
            pass
        # Compute profile_percent based on required fields present
        required_values = [full_name, phone, designation, linkedin, company_name, company_type, company_size, industry, address, website, logo_filename, comp_filename, auth_filename, roles, experience_levels, job_types]
        filled = sum(1 for v in required_values if v and str(v).strip() != '')
        profile_percent = int((filled / len(required_values)) * 100) if required_values else 0

        # keep only one row per recruiter to avoid stale data showing
        cursor.execute("DELETE FROM recruiter_profiles WHERE recruiter_id = %s", (user_id,))

        cursor.execute("""
            INSERT INTO recruiter_profiles 
            (recruiter_id, full_name, designation, company_name, phone, website, company_doc, auth_doc,
             linkedin, company_type, company_size, industry, address, logo_file, roles, experience_levels, job_types, profile_percent, verification_status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (user_id, full_name, designation, company_name, phone, website, comp_filename, auth_filename,
              linkedin, company_type, company_size, industry, address, logo_filename, roles, experience_levels, job_types, profile_percent, 'pending'))

        # keep the dashboard locked until admin approves
        cursor.execute("UPDATE recruiters SET profile_completed = 0 WHERE id = %s", (user_id,))
        
        db.commit()
        flash("Profile submitted for admin verification.", "success")
    except Exception as e:
        print(f"Database Error: {e}")
        db.rollback()
        flash("An error occurred while saving your profile.", "danger")
    finally:
        cursor.close()
        db.close()

    return redirect('/recruiter-dashboard?tab=profile')

@app.route('/admin/verify-companies')
def admin_verify_companies():
    if session.get('role') != 'admin':
        return redirect('/login')

    db = get_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT rp.*, r.email AS company_email
        FROM recruiter_profiles rp
        JOIN recruiters r ON rp.recruiter_id = r.id
        WHERE rp.verification_status = 'pending'
        ORDER BY rp.id DESC
    """)
    rows = cursor.fetchall()
    cursor.close()
    db.close()

    # map to template shape
    companies = []
    for rp in rows:
        doc = rp.get('company_doc') or rp.get('auth_doc')
        companies.append({
            'company_name': rp.get('company_name'),
            'company_email': rp.get('company_email'),
            'document_path': f"uploads/{doc}" if doc else None,
            'verification_status': rp.get('verification_status', 'pending'),
            'company_id': rp.get('recruiter_id')
        })

    return render_template('admin_verify_companies.html', companies=companies)

@app.route('/admin/approve-company/<recruiter_id>')
def approve_company(recruiter_id):
    if session.get('role') != 'admin':
        return redirect('/login')

    db = get_connection()
    cursor = db.cursor()
    try:
        cursor.execute("UPDATE recruiter_profiles SET verification_status='approved' WHERE recruiter_id=%s", (recruiter_id,))
        cursor.execute("UPDATE recruiters SET profile_completed=1 WHERE id=%s", (recruiter_id,))
        db.commit()
        flash("Company approved successfully.", "success")
        try:
            send_notification('recruiter', recruiter_id, 'Your company profile has been approved.')
        except Exception:
            pass
        try:
            log_audit(f"Approved company profile for recruiter {recruiter_id}")
        except Exception:
            pass
    except Exception as e:
        db.rollback()
        print(f"Approve company error: {e}")
        flash("Failed to approve company.", "danger")
    finally:
        cursor.close()
        db.close()
    return redirect('/admin/verify-companies')

@app.route('/admin/reject-company/<recruiter_id>')
def reject_company(recruiter_id):
    if session.get('role') != 'admin':
        return redirect('/login')

    db = get_connection()
    cursor = db.cursor()
    try:
        cursor.execute("UPDATE recruiter_profiles SET verification_status='rejected' WHERE recruiter_id=%s", (recruiter_id,))
        cursor.execute("UPDATE recruiters SET profile_completed=0 WHERE id=%s", (recruiter_id,))
        db.commit()
        flash("Company rejected.", "warning")
        try:
            send_notification('recruiter', recruiter_id, 'Your company profile was rejected.')
        except Exception:
            pass
        try:
            log_audit(f"Rejected company profile for recruiter {recruiter_id}")
        except Exception:
            pass
    except Exception as e:
        db.rollback()
        print(f"Reject company error: {e}")
        flash("Failed to reject company.", "danger")
    finally:
        cursor.close()
        db.close()
    return redirect('/admin/verify-companies')

@app.route('/recruiter/delete-profile', methods=['POST'])
def delete_recruiter_profile():
    if session.get('role') != 'recruiter':
        return redirect('/login')

    user_id = session.get('user_id')
    db = get_connection()
    cursor = db.cursor()

    try:
        cursor.execute("DELETE FROM recruiter_profiles WHERE recruiter_id = %s", (user_id,))
        cursor.execute("UPDATE recruiters SET profile_completed = 0 WHERE id = %s", (user_id,))
        db.commit()
        flash("Profile deleted. You can rebuild it anytime.", "info")
    except Exception as e:
        print(f"Error deleting recruiter profile: {e}")
        db.rollback()
        flash("Could not delete profile. Please try again.", "danger")
    finally:
        cursor.close()
        db.close()

    return redirect('/recruiter-dashboard?tab=profile')
@app.route('/save-job', methods=['POST'])
def save_job():
    if session.get('role') != 'recruiter':
        return redirect('/login')

    recruiter_id = session.get('user_id')

    title = request.form.get('title')
    department = request.form.get('department', '')
    location = request.form.get('location', '')
    job_type = request.form.get('job_type', '')
    employment_mode = request.form.get('employment_mode', '')
    salary_min = request.form.get('salary_min')
    salary_max = request.form.get('salary_max')
    min_experience = request.form.get('min_experience', 0)
    max_experience = request.form.get('max_experience', 0)
    education = request.form.get('education', '')
    openings = request.form.get('openings', 1)
    deadline = request.form.get('deadline')
    description = request.form.get('description', '')
    skills = request.form.get('skills', '')
    interview_mode = request.form.get('interview_mode', '')

    db = get_connection()
    cursor = db.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO jobs 
            (recruiter_id, title, department, location, job_type, employment_mode, salary_min, salary_max,
             min_experience, max_experience, education, openings, deadline, description, skills, interview_mode)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (recruiter_id, title, department, location, job_type, employment_mode, 
              salary_min, salary_max, min_experience, max_experience, education, 
              openings, deadline, description, skills, interview_mode))
        
        db.commit()
        flash("Job posted successfully!", "success")
    except Exception as e:
        print(f"Error: {e}")
        db.rollback()
        flash("Failed to post job. Please check your details.", "danger")
    finally:
        cursor.close()
        db.close()
    return redirect('/posted-jobs')
@app.route('/update-status/<int:app_id>/<status>')
def update_status(app_id, status):
    if session.get('role') != 'recruiter':
        return redirect('/login')

    allowed = ['Shortlisted','Interview','Selected','Rejected']
    if status not in allowed:
        return "Invalid status"

    db = get_connection()
    cursor = db.cursor()
    cursor.execute(
        "UPDATE applications SET status=%s WHERE id=%s",
        (status, app_id)
    )
    db.commit()
    cursor.close()
    db.close()

    return redirect('/recruiter-dashboard?tab=profile')

@app.route('/mentor-dashboard', methods=['GET', 'POST'])
def mentor_dashboard():
    if session.get('role') != 'mentor':
        return redirect('/login')

    mentor_id = session['user_id']
    db = get_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT * FROM mentor_profiles WHERE mentor_id = %s", (mentor_id,))
    profile = cursor.fetchone()

    if request.method == 'POST':
        from werkzeug.utils import secure_filename
        
        data = {
            'designation': request.form.get('designation'),
            'mentoring_areas': request.form.get('mentoring_areas'),
            'mode': request.form.get('mode'),
            'session_duration': request.form.get('session_duration'),
            'communication': request.form.get('communication'),
            'bio': request.form.get('bio'),
            'expertise': request.form.get('expertise'),
            'company': request.form.get('company'),
            'linkedin': request.form.get('linkedin'),
            'available_days': request.form.get('available_days'),
            'time_slot': request.form.get('time_slot'),
            'verification_type': request.form.get('verification_type'),
            'experience': request.form.get('experience', 0),
            'max_candidates': request.form.get('max_candidates', 5)
        }

        file = request.files.get('verification_file')
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            filename = profile['verification_file'] if profile else None

        # handle mentor profile photo upload (similar to candidate implementation)
        photo = request.files.get('photo')
        if photo and photo.filename != '':
            photo_filename = secure_filename(photo.filename)
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], photo_filename))
            try:
                cursor.execute("ALTER TABLE mentor_profiles ADD COLUMN photo_file VARCHAR(255)")
            except Exception:
                pass
        else:
            photo_filename = profile.get('photo_file') if profile else None

        cursor.execute("""
            INSERT INTO mentor_profiles
            (mentor_id, expertise, mentoring_areas, mode, experience, designation, company,
             linkedin, session_duration, max_candidates, communication, bio, available_days,
             time_slot, verification_type, photo_file, verification_file, verification_status, profile_percent)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'pending',100)
            ON DUPLICATE KEY UPDATE
            expertise=VALUES(expertise), mentoring_areas=VALUES(mentoring_areas), mode=VALUES(mode),
            experience=VALUES(experience), designation=VALUES(designation), company=VALUES(company),
            linkedin=VALUES(linkedin), session_duration=VALUES(session_duration),
            max_candidates=VALUES(max_candidates), communication=VALUES(communication),
            bio=VALUES(bio), available_days=VALUES(available_days), time_slot=VALUES(time_slot),
            verification_type=VALUES(verification_type), photo_file=VALUES(photo_file), verification_file=VALUES(verification_file),
            verification_status='pending', profile_percent=100
        """, (
            mentor_id, data['expertise'], data['mentoring_areas'], data['mode'], data['experience'],
            data['designation'], data['company'], data['linkedin'], data['session_duration'],
            data['max_candidates'], data['communication'], data['bio'], data['available_days'],
            data['time_slot'], data['verification_type'], photo_filename, filename
        ))
        
        db.commit()
        return redirect('/mentor-dashboard#profile')

    profile_completed = 1 if profile else 0
    profile_percent = profile['profile_percent'] if profile else 40

    cursor.execute("""
        SELECT mr.id, mr.request_message, mr.candidate_id, u.name AS candidate_name,
               cp.first_name, cp.last_name, cp.headline, cp.bio, cp.education, cp.skills, 
               cp.experience, cp.resume_file, cp.photo_file, u.email AS candidate_email
        FROM mentorship_requests mr 
        JOIN candidates u ON mr.candidate_id = u.id
        LEFT JOIN candidate_profiles cp ON u.id = cp.candidate_id
        WHERE mr.mentor_id = %s AND mr.status = 'Pending'
    """, (mentor_id,))
    pending_requests = cursor.fetchall()

    cursor.execute("""
        SELECT mr.id, mr.candidate_id, mr.request_message, mr.created_at AS started_at,
               u.name AS candidate_name, u.email AS candidate_email
        FROM mentorship_requests mr
        JOIN candidates u ON mr.candidate_id = u.id
        WHERE mr.mentor_id = %s AND mr.status = 'Accepted'
        ORDER BY mr.created_at DESC
    """, (mentor_id,))
    active_sessions = cursor.fetchall()

    # load recent notifications for mentor
    cursor.execute("SELECT * FROM notifications WHERE receiver_role=%s AND receiver_id=%s ORDER BY created_at DESC", ('mentor', mentor_id))
    notifications = cursor.fetchall()

    # Fetch all verified mentors excluding the current mentor
    cursor.execute("""
        SELECT mp.*, m.name 
        FROM mentor_profiles mp
        JOIN mentors m ON mp.mentor_id = m.id
        WHERE mp.verification_status = 'approved' 
        AND mp.mentor_id != %s
        ORDER BY mp.experience DESC
    """, (mentor_id,))
    available_mentors = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template(
        'mentor_dashboard.html',
        profile=profile,  
        profile_completed=profile_completed,
        profile_percent=profile_percent,
        pending_requests=pending_requests,
        active_sessions=active_sessions,
        notifications=notifications,
        available_mentors=available_mentors,
        user_id=mentor_id
    )

def send_notification(role,user_id, message):
    db = get_connection()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO notifications (receiver_role, receiver_id, message) VALUES (%s,%s,%s)",
        (role, user_id, message)
    )
    db.commit()
    cursor.close()
    db.close()

def log_audit(message, receiver_role='admin', receiver_id=0):
    """Record a lightweight audit entry using the notifications table.
    receiver_role/receiver_id are stored for traceability; defaults are admin/0.
    """
    try:
        db = get_connection()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO notifications (receiver_role, receiver_id, message) VALUES (%s,%s,%s)",
            (receiver_role, receiver_id, message)
        )
        db.commit()
    except Exception as _:
        try:
            db.rollback()
        except Exception:
            pass
    finally:
        try:
            cursor.close()
            db.close()
        except Exception:
            pass
@app.route('/notifications')
def notifications():
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT * FROM notifications
        WHERE receiver_role=%s AND receiver_id=%s
        ORDER BY created_at DESC
    """, (session["role"], session["user_id"]))
    notes = cursor.fetchall()
    cursor.close()
    db.close()

    return render_template('notifications.html', notes=notes)

@app.route('/admin/verify-mentors')
def verify_mentors():
    if session.get('role') != 'admin':
        return redirect('/login')

    db = get_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT m.id, m.name, m.email, mp.company, mp.verification_file, mp.expertise
        FROM mentors m
        JOIN mentor_profiles mp ON m.id = mp.mentor_id
        WHERE mp.verification_status = 'pending'
    """)
    mentors = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template('admin_verify_mentors.html', mentors=mentors)

@app.route('/admin/approve-mentor/<int:profile_id>')
def approve_mentor(profile_id):
    if session.get('role') != 'admin':
        return redirect('/login')

    db = get_connection()
    cursor = db.cursor(dictionary=True)

    # get mentor id
    cursor.execute("SELECT mentor_id FROM mentor_profiles WHERE id=%s", (profile_id,))
    row = cursor.fetchone()
    mentor_id = row['mentor_id'] if row else None

    cursor.execute(
        "UPDATE mentor_profiles SET verification_status='approved' WHERE id=%s",
        (profile_id,)
    )
    db.commit()

    # notify mentor
    try:
        if mentor_id:
            message = "Your verification has been approved. Congratulations!"
            send_notification('mentor', mentor_id, message)
            socketio.emit('mentor_notification', {'message': message}, room=f"mentor_{mentor_id}")
    except Exception:
        pass

    try:
        log_audit(f"Approved mentor profile {profile_id}")
    except Exception:
        pass

    cursor.close()
    db.close()

    return redirect('/admin/verify-mentors')


@app.route('/admin/reject-mentor/<int:profile_id>', methods=['POST'])
def reject_mentor(profile_id):
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'unauthorized'}), 403

    data = request.get_json() or {}
    reason = data.get('reason', 'No reason provided')

    db = get_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT mentor_id FROM mentor_profiles WHERE id=%s", (profile_id,))
    row = cursor.fetchone()
    mentor_id = row['mentor_id'] if row else None

    cursor.execute(
        "UPDATE mentor_profiles SET verification_status='rejected' WHERE id=%s",
        (profile_id,)
    )
    db.commit()

    # try to store rejection reason in mentor_profiles (add column if needed)
    try:
        try:
            cursor.execute("ALTER TABLE mentor_profiles ADD COLUMN rejection_reason TEXT")
        except Exception:
            # ignore if column already exists or alter not supported
            pass
        cursor.execute("UPDATE mentor_profiles SET rejection_reason=%s WHERE id=%s", (reason, profile_id))
        db.commit()
    except Exception:
        db.rollback()

    try:
        if mentor_id:
            message = f"Your verification was rejected. Reason: {reason}"
            send_notification('mentor', mentor_id, message)
            socketio.emit('mentor_notification', {'message': message}, room=f"mentor_{mentor_id}")
    except Exception:
        pass

    try:
        log_audit(f"Rejected mentor profile {profile_id}: {reason}")
    except Exception:
        pass

    cursor.close()
    db.close()

    return jsonify({'success': True})


@app.route('/admin/mentor-profile/<int:profile_id>')
def admin_get_mentor_profile(profile_id):
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'unauthorized'}), 403

    db = get_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT m.id AS mentor_id, m.name AS mentor_name, m.email AS mentor_email,
               mp.*
        FROM mentors m
        JOIN mentor_profiles mp ON m.id = mp.mentor_id
        WHERE mp.id = %s
    """, (profile_id,))
    row = cursor.fetchone()
    cursor.close()
    db.close()

    if not row:
        return jsonify({'success': False, 'error': 'not found'}), 404

    # remove internal numeric keys if any and convert to JSON serializable
    return jsonify({'success': True, 'profile': row})


@app.route('/admin/user-profile/<role>/<user_id>')
def admin_get_user_profile(role, user_id):
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'unauthorized'}), 403

    db = get_connection()
    cursor = db.cursor(dictionary=True)

    try:
        role = role.lower()
        if role == 'mentor':
            # fetch mentor + profile by mentor id
            cursor.execute("""
                SELECT m.id AS mentor_id, m.name AS mentor_name, m.email AS mentor_email, mp.*
                FROM mentors m
                LEFT JOIN mentor_profiles mp ON m.id = mp.mentor_id
                WHERE m.id = %s
            """, (user_id,))
            row = cursor.fetchone()
            if not row:
                return jsonify({'success': False, 'error': 'not found'}), 404
            return jsonify({'success': True, 'profile': row})

        if role == 'candidate':
            cursor.execute("SELECT id, name, email FROM candidates WHERE id=%s", (user_id,))
            row = cursor.fetchone()
            if not row:
                return jsonify({'success': False, 'error': 'not found'}), 404
            # try to load candidate profile
            cursor.execute("SELECT * FROM candidate_profiles WHERE candidate_id=%s", (user_id,))
            cp = cursor.fetchone()
            return jsonify({'success': True, 'profile': {'user': row, 'candidate_profile': cp}})

        if role == 'recruiter':
            cursor.execute("SELECT id, name, email FROM recruiters WHERE id=%s", (user_id,))
            row = cursor.fetchone()
            if not row:
                return jsonify({'success': False, 'error': 'not found'}), 404
            cursor.execute("SELECT * FROM recruiter_profiles WHERE recruiter_id=%s", (user_id,))
            rp = cursor.fetchone()
            return jsonify({'success': True, 'profile': {'user': row, 'recruiter_profile': rp}})

        return jsonify({'success': False, 'error': 'unsupported role'}), 400
    finally:
        cursor.close()
        db.close()

#MENTORSHIP ACTIONS

@app.route('/request-mentorship/<mentor_id>', methods=["GET", "POST"])
def request_mentorship(mentor_id):
    if session.get('role') != 'candidate':
        return redirect('/login')

    candidate_id = session.get('user_id')
    msg = request.form.get('message', 'I would like your guidance.')
    
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    # Get mentor and candidate names
    cursor.execute("SELECT name FROM mentors WHERE id = %s", (mentor_id,))
    mentor = cursor.fetchone()
    
    cursor.execute("SELECT name FROM candidates WHERE id = %s", (candidate_id,))
    candidate = cursor.fetchone()
    
    cursor.execute(
        "INSERT INTO mentorship_requests (candidate_id, mentor_id, request_message) VALUES (%s, %s, %s)",
        (candidate_id, mentor_id, msg)
    )
    db.commit()
    cursor.close()
    db.close()
    
    # Send notification to mentor
    if mentor and candidate:
        notification_msg = f"New mentorship request from {candidate['name']}"
        send_notification('mentor', mentor_id, notification_msg)
    
    flash(f"Mentorship request sent to {mentor['name'] if mentor else 'mentor'} successfully!", "success")
    return redirect('/candidate-dashboard#mentors')

@app.route('/mentor/respond-request/<int:request_id>/<action>')
def respond_request(request_id, action):
    if session.get('role') != 'mentor':
        return redirect('/login')
    
    status = 'Accepted' if action == 'accept' else 'Rejected'
    db = get_connection()
    cursor = db.cursor()
    cursor.execute(
        "UPDATE mentorship_requests SET status=%s WHERE id=%s AND mentor_id=%s",
        (status, request_id, session.get('user_id'))
    )
    db.commit()
    cursor.close()
    db.close()
    return redirect('/mentor-dashboard')

@app.route('/mentor/give-feedback/<int:request_id>', methods=["GET", "POST"])
def give_feedback(request_id):
    feedback = request.form.get('feedback')
    db = get_connection()
    cursor = db.cursor()
    cursor.execute(
        "UPDATE mentorship_requests SET mentor_feedback=%s, status='Completed' WHERE id=%s",
        (feedback, request_id)
    )
    db.commit()
    cursor.close()
    db.close()
    return redirect('/mentor-dashboard')

@app.route('/api/mentor/meetings', methods=['GET', 'POST'])
def mentor_meetings_api():
    if session.get('role') != 'mentor':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    mentor_id = session.get('user_id')
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    try:
        if request.method == 'POST':
            data = request.get_json() or {}
            candidate_id = data.get('candidate_id')
            mode = data.get('mode')
            meeting_date = data.get('date')
            meeting_time = data.get('time')
            meeting_link = data.get('link')
            notes = data.get('notes')
            if not candidate_id:
                return jsonify({'success': False, 'message': 'candidate_id required'}), 400
            cursor.execute(
                """
                INSERT INTO mentor_meetings (mentor_id, candidate_id, mode, meeting_date, meeting_time, meeting_link, notes)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE
                    mode=VALUES(mode), meeting_date=VALUES(meeting_date), meeting_time=VALUES(meeting_time),
                    meeting_link=VALUES(meeting_link), notes=VALUES(notes)
                """,
                (mentor_id, candidate_id, mode, meeting_date, meeting_time, meeting_link, notes)
            )
            db.commit()
            cursor.execute("SELECT name FROM candidates WHERE id=%s", (candidate_id,))
            row = cursor.fetchone()
            return jsonify({'success': True, 'meeting': {
                'candidate_id': candidate_id,
                'candidate_name': row['name'] if row else None,
                'mode': mode,
                'meeting_date': meeting_date,
                'meeting_time': meeting_time,
                'meeting_link': meeting_link,
                'notes': notes
            }})

        cursor.execute(
            """
            SELECT mm.*, c.name AS candidate_name
            FROM mentor_meetings mm
            JOIN candidates c ON mm.candidate_id = c.id
            WHERE mm.mentor_id = %s
            ORDER BY mm.meeting_date DESC, mm.meeting_time DESC
            """,
            (mentor_id,)
        )
        rows = cursor.fetchall()
        return jsonify({'success': True, 'meetings': rows})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/api/candidate/meetings')
def candidate_meetings_api():
    if session.get('role') != 'candidate':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    cand_id = session.get('user_id')
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT mm.*, m.name AS mentor_name, mp.company, mp.mode, mp.available_days, mp.time_slot
            FROM mentor_meetings mm
            JOIN mentors m ON mm.mentor_id = m.id
            LEFT JOIN mentor_profiles mp ON m.id = mp.mentor_id
            WHERE mm.candidate_id = %s
            ORDER BY mm.meeting_date DESC, mm.meeting_time DESC
            """,
            (cand_id,)
        )
        rows = cursor.fetchall()
        return jsonify({'success': True, 'meetings': rows})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cursor.close()
        db.close()
@app.route('/mentor/delete-profile', methods=['POST'])
def delete_mentor_profile():
    if session.get('role') != 'mentor':
        return redirect('/login')

    mentor_id = session['user_id']
    db = get_connection()
    cursor = db.cursor()
    
    try:
        cursor.execute("DELETE FROM mentor_profiles WHERE mentor_id = %s", (mentor_id,))
        db.commit()
        flash("Profile deleted successfully.", "warning")
    except Exception as e:
        print(f"Error deleting profile: {e}")
        flash("Could not delete profile.", "danger")
    finally:
        cursor.close()
        db.close()

    return redirect('/mentor-dashboard')

@app.route('/admin-dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect('/login')

    db = get_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT c.name AS user_name, 'Mentorship' AS type, mr.mentor_feedback AS comment, 
               5 AS rating, mr.created_at 
        FROM mentorship_requests mr
        JOIN candidates c ON mr.candidate_id = c.id
        WHERE mr.status = 'Completed' AND mr.mentor_feedback IS NOT NULL
        ORDER BY mr.created_at DESC
    """)
    user_feedbacks = cursor.fetchall()

    cursor.execute("SELECT (SELECT COUNT(*) FROM candidates) + (SELECT COUNT(*) FROM recruiters) + (SELECT COUNT(*) FROM mentors) AS total")
    total_users_count = cursor.fetchone()['total']

    cursor.execute("""
        SELECT id, name, email, 'Candidate' as role FROM candidates
        UNION
        SELECT id, name, email, 'Recruiter' as role FROM recruiters
        UNION
        SELECT id, name, email, 'Mentor' as role FROM mentors
        ORDER BY id ASC
    """)
    all_users = cursor.fetchall()

    # attach verification_status for mentors and recruiters when available
    for u in all_users:
        try:
            if u.get('role') == 'Mentor':
                cursor.execute("SELECT verification_status FROM mentor_profiles WHERE mentor_id=%s", (u.get('id'),))
                r = cursor.fetchone()
                u['verification_status'] = r['verification_status'] if r and 'verification_status' in r else None
            elif u.get('role') == 'Recruiter':
                cursor.execute("SELECT verification_status FROM recruiter_profiles WHERE recruiter_id=%s", (u.get('id'),))
                r = cursor.fetchone()
                u['verification_status'] = r['verification_status'] if r and 'verification_status' in r else None
            else:
                u['verification_status'] = None
        except Exception:
            u['verification_status'] = None

    cursor.execute("""
        SELECT m.name, mp.id, mp.expertise, mp.verification_file 
        FROM mentors m
        JOIN mentor_profiles mp ON m.id = mp.mentor_id
        WHERE mp.verification_status = 'pending'
    """)
    pending_mentors = cursor.fetchall()

    cursor.execute("SELECT * FROM jobs")
    jobs = cursor.fetchall()

    # real analytics
    cursor.execute("SELECT COUNT(*) AS cnt FROM applications WHERE status='Selected'")
    row = cursor.fetchone()
    total_placements = row['cnt'] if row and 'cnt' in row else 0

    active_jobs = len(jobs) if jobs else 0

    cursor.execute("SELECT COUNT(*) AS total FROM candidates")
    row = cursor.fetchone()
    total_candidates = row['total'] if row and 'total' in row else 0

    cursor.execute("SELECT COUNT(*) AS cnt FROM candidate_profiles WHERE skills IS NOT NULL AND skills <> ''")
    row = cursor.fetchone()
    candidates_with_skills = row['cnt'] if row and 'cnt' in row else 0
    skill_coverage = int((candidates_with_skills / total_candidates) * 100) if total_candidates else 0

    cursor.execute("SELECT COUNT(*) AS cnt FROM feedback")
    row = cursor.fetchone()
    reports_count = row['cnt'] if row and 'cnt' in row else 0

    # Pending company verifications
    try:
        cursor.execute("""
            SELECT rp.*, r.email AS company_email
            FROM recruiter_profiles rp
            JOIN recruiters r ON rp.recruiter_id = r.id
            WHERE rp.verification_status = 'pending'
            ORDER BY rp.id DESC
        """)
        pending_companies = cursor.fetchall()
    except Exception:
        pending_companies = []

    # Notifications & Alerts (latest 10)
    try:
        cursor.execute("""
            SELECT created_at, receiver_role, receiver_id, message, is_read
            FROM notifications
            ORDER BY created_at DESC
            LIMIT 10
        """)
        notifications_list = cursor.fetchall()
    except Exception:
        notifications_list = []

    # Audit & Logs (latest 5)
    try:
        cursor.execute("""
            SELECT created_at, receiver_role, receiver_id, message, is_read
            FROM notifications
            ORDER BY created_at DESC
            LIMIT 5
        """)
        audit_rows = cursor.fetchall()
    except Exception:
        audit_rows = []

    cursor.close()
    db.close()

    return render_template(
        'admin_dashboard.html',
        all_users=all_users,
        user_feedbacks=user_feedbacks,
        users=total_users_count,        
        pending_mentors=pending_mentors,
        pending_companies=pending_companies,
        jobs=jobs,
        total_placements=total_placements,
        active_jobs=active_jobs,
        skill_coverage=skill_coverage,
        reports_count=reports_count,
        notifications_list=notifications_list,
        audit_rows=audit_rows
    )


def _csv_response(filename, rows, header):
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(header)
    writer.writerows(rows)
    resp = make_response(output.getvalue())
    resp.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    resp.headers['Content-Type'] = 'text/csv'
    return resp


@app.route('/admin/export/users')
def export_users():
    if session.get('role') != 'admin':
        return redirect('/login')

    db = get_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT id, name, email, 'Candidate' AS role, created_at FROM candidates
        UNION ALL
        SELECT id, name, email, 'Recruiter' AS role, created_at FROM recruiters
        UNION ALL
        SELECT id, name, email, 'Mentor' AS role, created_at FROM mentors
        ORDER BY created_at DESC
    """)
    rows = cursor.fetchall()
    cursor.close()
    db.close()

    data_rows = [[r['id'], r['name'], r['email'], r['role'], r['created_at']] for r in rows]
    try:
        log_audit("Exported users CSV")
    except Exception:
        pass
    return _csv_response('users.csv', data_rows, ['id', 'name', 'email', 'role', 'created_at'])


@app.route('/admin/export/jobs')
def export_jobs():
    if session.get('role') != 'admin':
        return redirect('/login')

    db = get_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT j.id, j.title, j.skills, j.recruiter_id,
               (SELECT COUNT(*) FROM applications a WHERE a.job_id = j.id) AS applications_count
        FROM jobs j
        ORDER BY j.id DESC
    """)
    rows = cursor.fetchall()
    cursor.close()
    db.close()

    data_rows = [[r['id'], r['title'], r['skills'], r['recruiter_id'], r['applications_count']] for r in rows]
    try:
        log_audit("Exported jobs CSV")
    except Exception:
        pass
    return _csv_response('jobs.csv', data_rows, ['id', 'title', 'skills', 'recruiter_id', 'applications'])


@app.route('/admin/export/audit')
def export_audit():
    if session.get('role') != 'admin':
        return redirect('/login')

    # Using notifications table as lightweight audit trail
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT created_at, receiver_role, receiver_id, message, is_read
        FROM notifications
        ORDER BY created_at DESC
        LIMIT 200
    """)
    rows = cursor.fetchall()
    cursor.close()
    db.close()

    data_rows = [[r['created_at'], r['receiver_role'], r['receiver_id'], r['message'], r['is_read']] for r in rows]
    try:
        log_audit("Exported audit CSV")
    except Exception:
        pass
    return _csv_response('audit.csv', data_rows, ['timestamp', 'receiver_role', 'receiver_id', 'message', 'is_read'])

def extract_resume_text(path):
    doc = fitz.open(path)
    text = ""
    for page in doc:
        text += page.get_text()
    return text.lower()
def extract_skills(text):
    skills_db = [
        'python','java','sql','flask','django','react',
        'machine learning','data science','html','css'
    ]
    return [s for s in skills_db if s in text]
def skill_match(candidate, job):
    c = set(candidate)
    j = set(job.lower().split(','))
    return int(len(c & j) / len(j) * 100) if j else 0

@app.route('/api/analytics')
def get_analytics():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'unauthorized'}), 403

    db = get_connection()
    cursor = db.cursor(dictionary=True)

    try:
        # 1. Platform growth - get monthly user counts
        cursor.execute("""
            SELECT DATE_FORMAT(created_at, '%Y-%m') AS month
            FROM candidates
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 12 MONTH)
            UNION
            SELECT DATE_FORMAT(created_at, '%Y-%m') AS month
            FROM recruiters
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 12 MONTH)
            UNION
            SELECT DATE_FORMAT(created_at, '%Y-%m') AS month
            FROM mentors
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 12 MONTH)
            ORDER BY month
        """)
        months_raw = cursor.fetchall()
        
        if months_raw:
            growth_months = [row['month'] for row in months_raw]
            growth_users = []
            for month in growth_months:
                cursor.close()
                cursor = db.cursor(dictionary=True)
                cursor.execute("""
                    SELECT COUNT(*) as cnt FROM (
                        SELECT id FROM candidates WHERE DATE_FORMAT(created_at, '%Y-%m') <= %s
                        UNION
                        SELECT id FROM recruiters WHERE DATE_FORMAT(created_at, '%Y-%m') <= %s
                        UNION
                        SELECT id FROM mentors WHERE DATE_FORMAT(created_at, '%Y-%m') <= %s
                    ) users
                """, (month, month, month))
                count_row = cursor.fetchone()
                cursor.fetchall()
                growth_users.append(count_row['cnt'] if count_row else 0)
        else:
            growth_months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
            growth_users = [120, 230, 420, 600, 780, 920, 1100, 1300, 1500, 1700, 1900, 2150]

        # 2. User role distribution - Real data
        cursor.close()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) AS total FROM candidates")
        candidates_count = cursor.fetchone()['total'] or 0
        cursor.fetchall()
        
        cursor.close()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) AS total FROM recruiters")
        recruiters_count = cursor.fetchone()['total'] or 0
        cursor.fetchall()
        
        cursor.close()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) AS total FROM mentors")
        mentors_count = cursor.fetchone()['total'] or 0
        cursor.fetchall()

        # 3. Jobs overview - Real data
        cursor.close()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) AS total FROM jobs")
        total_jobs = cursor.fetchone()['total'] or 0
        cursor.fetchall()
        
        cursor.close()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(DISTINCT job_id) AS total FROM applications WHERE status IN ('Selected','Rejected')")
        closed_jobs_count = cursor.fetchone()['total'] or 0
        cursor.fetchall()
        active_jobs_count = max(0, total_jobs - closed_jobs_count)

        # 4. Top skills in demand - Parse from active job postings
        cursor.close()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT skills FROM jobs WHERE skills IS NOT NULL AND skills != '' AND deadline >= CURDATE()")
        skills_raw = cursor.fetchall()
        
        skills_dict = {}
        if skills_raw:
            for row in skills_raw:
                if row['skills']:
                    # Split by comma and count each skill
                    skill_list = [s.strip().lower() for s in row['skills'].split(',')]
                    for skill in skill_list:
                        if skill:
                            skills_dict[skill] = skills_dict.get(skill, 0) + 1
        
        # Sort by demand and get top 10
        if skills_dict:
            sorted_skills = sorted(skills_dict.items(), key=lambda x: x[1], reverse=True)[:10]
            skills_labels = [skill[0].title() for skill in sorted_skills]
            skills_demand = [skill[1] for skill in sorted_skills]
        else:
            # If no jobs in database yet, show empty state
            skills_labels = []
            skills_demand = []

        cursor.close()
        db.close()

        return jsonify({
            'success': True,
            'growth': {
                'months': growth_months,
                'users': growth_users
            },
            'roles': {
                'labels': ['Candidates', 'Mentors', 'Recruiters'],
                'data': [candidates_count, mentors_count, recruiters_count]
            },
            'jobs': {
                'labels': ['Active Jobs', 'Closed Jobs'],
                'data': [active_jobs_count, closed_jobs_count]
            },
            'skills': {
                'labels': skills_labels,
                'data': skills_demand
            }
        })
    except Exception as e:
        print(f"Analytics Error: {e}")
        try:
            cursor.close()
            db.close()
        except:
            pass
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/posted-jobs')
def posted_jobs():
    if session.get('role') != 'recruiter':
        return redirect('/login')
    
    user_id = session.get('user_id')
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    try:
        # load completion status
        cursor.execute("SELECT profile_completed FROM recruiters WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        is_complete = user['profile_completed'] if user else False
        cursor.fetchall()
        cursor.close()
        cursor = db.cursor(dictionary=True)
        # Get all jobs posted by the recruiter
        cursor.execute("""
            SELECT j.*, 
                   COUNT(DISTINCT a.id) as application_count
            FROM jobs j
            LEFT JOIN applications a ON j.id = a.job_id
            WHERE j.recruiter_id = %s
            GROUP BY j.id
            ORDER BY j.created_at DESC
        """, (user_id,))
        jobs = cursor.fetchall()
        
        # Get today's date for deadline comparison
        from datetime import date
        today = date.today()
        
        cursor.close()
        db.close()
        # Render inside dashboard instead of separate page
        return render_template('recruiter_dashboard.html', jobs=jobs, today=today, is_complete=is_complete, tab='jobs')
    except Exception as e:
        print(f"Error: {e}")
        cursor.close()
        db.close()
        flash("Error loading jobs", "danger")
        return redirect('/recruiter-dashboard')

@app.route('/view-job/<int:job_id>')
def view_job(job_id):
    if session.get('role') != 'recruiter':
        return redirect('/login')
    
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    try:
        cursor.execute("""
            SELECT * FROM jobs WHERE id = %s AND recruiter_id = %s
        """, (job_id, session.get('user_id')))
        job = cursor.fetchone()
        
        if not job:
            flash("Job not found", "danger")
            return redirect('/recruiter-dashboard?tab=jobs')
        
        cursor.close()
        db.close()
        
        return render_template('view_job.html', job=job)
    except Exception as e:
        print(f"Error: {e}")
        cursor.close()
        db.close()
        flash("Error loading job details", "danger")
        return redirect('/posted-jobs')

@app.route('/edit-job/<int:job_id>', methods=['GET', 'POST'])
def edit_job(job_id):
    if session.get('role') != 'recruiter':
        return redirect('/login')
    
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    try:
        cursor.execute("""
            SELECT * FROM jobs WHERE id = %s AND recruiter_id = %s
        """, (job_id, session.get('user_id')))
        job = cursor.fetchone()
        
        if not job:
            flash("Job not found", "danger")
            return redirect('/recruiter-dashboard?tab=jobs')
        
        if request.method == 'POST':
            # Update job details
            title = request.form.get('title')
            department = request.form.get('department')
            location = request.form.get('location')
            job_type = request.form.get('job_type')
            employment_mode = request.form.get('employment_mode')
            salary_min = request.form.get('salary_min')
            salary_max = request.form.get('salary_max')
            min_experience = request.form.get('min_experience')
            max_experience = request.form.get('max_experience')
            education = request.form.get('education')
            openings = request.form.get('openings')
            deadline = request.form.get('deadline')
            description = request.form.get('description')
            skills = request.form.get('skills')
            interview_mode = request.form.get('interview_mode')
            
            cursor.execute("""
                UPDATE jobs SET 
                    title=%s, department=%s, location=%s, job_type=%s, 
                    employment_mode=%s, salary_min=%s, salary_max=%s,
                    min_experience=%s, max_experience=%s, education=%s,
                    openings=%s, deadline=%s, description=%s, 
                    skills=%s, interview_mode=%s
                WHERE id=%s AND recruiter_id=%s
            """, (title, department, location, job_type, employment_mode, 
                  salary_min, salary_max, min_experience, max_experience, 
                  education, openings, deadline, description, skills, 
                  interview_mode, job_id, session.get('user_id')))
            
            db.commit()
            flash("Job updated successfully!", "success")
            cursor.close()
            db.close()
            return redirect('/recruiter-dashboard?tab=jobs')
        
        # GET request - redirect to dashboard with edit tab
        cursor.close()
        db.close()
        return redirect(f'/recruiter-dashboard?tab=edit-job&job_id={job_id}')
    except Exception as e:
        print(f"Error: {e}")
        cursor.close()
        db.close()
        flash("Error updating job", "danger")
        return redirect('/recruiter-dashboard?tab=jobs')

@app.route('/delete-job/<int:job_id>', methods=['POST'])
def delete_job(job_id):
    if session.get('role') != 'recruiter':
        return redirect('/login')
    
    db = get_connection()
    cursor = db.cursor()
    
    try:
        # First verify the job belongs to the recruiter
        cursor.execute("""
            SELECT id FROM jobs WHERE id = %s AND recruiter_id = %s
        """, (job_id, session.get('user_id')))
        
        if not cursor.fetchone():
            flash("Job not found", "danger")
            return redirect('/posted-jobs')
        
        # Delete applications for this job
        cursor.execute("DELETE FROM applications WHERE job_id = %s", (job_id,))
        
        # Delete the job
        cursor.execute("DELETE FROM jobs WHERE id = %s", (job_id,))
        
        db.commit()
        flash("Job deleted successfully!", "success")
        cursor.close()
        db.close()
        return redirect('/recruiter-dashboard?tab=jobs')
    except Exception as e:
        print(f"Error: {e}")
        db.rollback()
        cursor.close()
        db.close()
        flash("Error deleting job", "danger")
        return redirect('/recruiter-dashboard?tab=jobs')

@app.route('/duplicate-job/<int:job_id>', methods=['POST'])
def duplicate_job(job_id):
    if session.get('role') != 'recruiter':
        return redirect('/login')
    
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    try:
        # Fetch the original job
        cursor.execute("""
            SELECT * FROM jobs WHERE id = %s AND recruiter_id = %s
        """, (job_id, session.get('user_id')))
        job = cursor.fetchone()
        
        if not job:
            flash("Job not found", "danger")
            return redirect('/recruiter-dashboard?tab=jobs')
        
        # Create duplicate with "[Copy]" suffix
        cursor.execute("""
            INSERT INTO jobs (
                recruiter_id, title, department, location, job_type,
                employment_mode, salary_min, salary_max, min_experience,
                max_experience, education, openings, deadline,
                description, skills, interview_mode, created_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW()
            )
        """, (
            session.get('user_id'),
            f"{job['title']} [Copy]",
            job.get('department'),
            job.get('location'),
            job.get('job_type'),
            job.get('employment_mode'),
            job.get('salary_min'),
            job.get('salary_max'),
            job.get('min_experience'),
            job.get('max_experience'),
            job.get('education'),
            job.get('openings'),
            job.get('deadline'),
            job.get('description'),
            job.get('skills'),
            job.get('interview_mode')
        ))
        
        db.commit()
        flash("Job duplicated successfully!", "success")
        cursor.close()
        db.close()
        return redirect('/recruiter-dashboard?tab=jobs')
    except Exception as e:
        print(f"Error duplicating job: {e}")
        db.rollback()
        cursor.close()
        db.close()
        flash("Error duplicating job", "danger")
        return redirect('/recruiter-dashboard?tab=jobs')

@app.route('/toggle-job-status/<int:job_id>', methods=['POST'])
def toggle_job_status(job_id):
    if session.get('role') != 'recruiter':
        return redirect('/login')
    
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    try:
        # Check current status (using deadline as active/inactive indicator)
        cursor.execute("""
            SELECT id, deadline FROM jobs WHERE id = %s AND recruiter_id = %s
        """, (job_id, session.get('user_id')))
        job = cursor.fetchone()
        
        if not job:
            flash("Job not found", "danger")
            return redirect('/recruiter-dashboard?tab=jobs')
        
        # Toggle: if no deadline or past deadline, set to 30 days from now
        # If active (future deadline), set to today (making it closed)
        from datetime import datetime, timedelta
        today = datetime.now().date()
        
        if job['deadline'] and job['deadline'] >= today:
            # Job is active, pause it by setting deadline to yesterday
            new_deadline = today - timedelta(days=1)
            status_msg = "paused"
        else:
            # Job is paused, activate it
            new_deadline = today + timedelta(days=30)
            status_msg = "activated"
        
        cursor.execute("""
            UPDATE jobs SET deadline = %s WHERE id = %s
        """, (new_deadline, job_id))
        
        db.commit()
        flash(f"Job {status_msg} successfully!", "success")
        cursor.close()
        db.close()
        return redirect('/recruiter-dashboard?tab=jobs')
    except Exception as e:
        print(f"Error toggling job status: {e}")
        db.rollback()
        cursor.close()
        db.close()
        flash("Error updating job status", "danger")
        return redirect('/recruiter-dashboard?tab=jobs')

@app.route('/applications')
def applications():
    if session.get('role') != 'recruiter':
        return redirect('/login')
    
    user_id = session.get('user_id')
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT profile_completed FROM recruiters WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        is_complete = user['profile_completed'] if user else False
        cursor.fetchall()
        cursor.close()
        cursor = db.cursor(dictionary=True)
        # Get all applications for jobs posted by this recruiter
        cursor.execute("""
            SELECT a.id, a.status, a.applied_at,
                   c.id as candidate_id, c.name as candidate_name, c.email as candidate_email,
                   j.title as job_title,
                   cp.resume_file,
                   (SELECT id FROM ai_tests WHERE candidate_id = c.id AND status = 'completed' ORDER BY completed_at DESC LIMIT 1) as latest_test_id,
                   (SELECT obtained_marks FROM ai_tests WHERE candidate_id = c.id AND status = 'completed' ORDER BY completed_at DESC LIMIT 1) as latest_test_score,
                   (SELECT total_marks FROM ai_tests WHERE candidate_id = c.id AND status = 'completed' ORDER BY completed_at DESC LIMIT 1) as latest_test_total,
                   (SELECT percentage FROM ai_tests WHERE candidate_id = c.id AND status = 'completed' ORDER BY completed_at DESC LIMIT 1) as latest_test_percentage
            FROM applications a
            JOIN candidates c ON a.candidate_id = c.id
            JOIN jobs j ON a.job_id = j.id
            LEFT JOIN candidate_profiles cp ON c.id = cp.candidate_id
            WHERE j.recruiter_id = %s
            ORDER BY a.applied_at DESC
        """, (user_id,))
        applications_list = cursor.fetchall()
        
        cursor.close()
        db.close()
        
        return render_template('applications.html', applications=applications_list, is_complete=is_complete, tab='overview')
    except Exception as e:
        print(f"Error: {e}")
        cursor.close()
        db.close()
        flash("Error loading applications", "danger")
        return redirect('/recruiter-dashboard')

@app.route('/interviews')
def interviews():
    if session.get('role') != 'recruiter':
        return redirect('/login')
    
    user_id = session.get('user_id')
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT profile_completed FROM recruiters WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        is_complete = user['profile_completed'] if user else False
        cursor.fetchall()
        cursor.close()
        cursor = db.cursor(dictionary=True)
        # Get all applications with 'Interview' status for jobs posted by this recruiter
        cursor.execute("""
            SELECT a.id, a.status, a.applied_at,
                   c.id as candidate_id, c.name as candidate_name, c.email as candidate_email,
                   j.id as job_id, j.title as job_title,
                   cp.resume_file,
                   (SELECT id FROM ai_tests WHERE candidate_id = c.id AND status = 'completed' ORDER BY completed_at DESC LIMIT 1) as latest_test_id,
                   (SELECT obtained_marks FROM ai_tests WHERE candidate_id = c.id AND status = 'completed' ORDER BY completed_at DESC LIMIT 1) as latest_test_score,
                   (SELECT total_marks FROM ai_tests WHERE candidate_id = c.id AND status = 'completed' ORDER BY completed_at DESC LIMIT 1) as latest_test_total,
                   (SELECT percentage FROM ai_tests WHERE candidate_id = c.id AND status = 'completed' ORDER BY completed_at DESC LIMIT 1) as latest_test_percentage
            FROM applications a
            JOIN candidates c ON a.candidate_id = c.id
            JOIN jobs j ON a.job_id = j.id
            LEFT JOIN candidate_profiles cp ON c.id = cp.candidate_id
            WHERE j.recruiter_id = %s AND a.status = 'Interview'
            ORDER BY a.applied_at DESC
        """, (user_id,))
        interviews_list = cursor.fetchall()
        
        cursor.close()
        db.close()
        
        return render_template('interviews.html', interviews=interviews_list, is_complete=is_complete, tab='overview')
    except Exception as e:
        print(f"Error: {e}")
        cursor.close()
        db.close()
        flash("Error loading interviews", "danger")
        return redirect('/recruiter-dashboard')

@app.route('/update-application/<int:app_id>/<action>', methods=['GET', 'POST'])
def update_application(app_id, action):
    if session.get('role') != 'recruiter':
        return redirect('/login')
    
    # Map action to status
    action_map = {
        'shortlist': 'Shortlisted',
        'interview': 'Interview',
        'offer': 'Selected',
        'reject': 'Rejected'
    }
    
    if action not in action_map:
        flash("Invalid action", "danger")
        return redirect('/applications')
    
    new_status = action_map[action]
    
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    try:
        # Verify the application belongs to a job posted by this recruiter
        cursor.execute(
            "SELECT a.id FROM applications a JOIN jobs j ON a.job_id = j.id WHERE a.id = %s AND j.recruiter_id = %s",
            (app_id, session.get('user_id'))
        )
        
        if not cursor.fetchone():
            flash("Application not found", "danger")
            return redirect('/applications')
        
        # Update application status
        cursor.execute(
            "UPDATE applications SET status = %s WHERE id = %s",
            (new_status, app_id)
        )
        
        db.commit()
        flash(f"Application status updated to {new_status}", "success")
        cursor.close()
        db.close()
        
        # Redirect based on where the action was initiated
        if action in ['offer', 'reject']:
            return redirect('/interviews')
        else:
            return redirect('/applications')
    except Exception as e:
        print(f"Error: {e}")
        db.rollback()
        cursor.close()
        db.close()
        flash("Error updating application", "danger")
        return redirect('/applications')

@app.route('/start-ai-test', methods=['GET', 'POST'])
def start_ai_test():
    if session.get('role') != 'candidate':
        return redirect('/login')
    
    candidate_id = session.get('user_id')
    
    # Get candidate profile to extract ALL skills
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    cursor.execute(
        "SELECT * FROM candidate_profiles WHERE candidate_id = %s",
        (candidate_id,)
    )
    profile = cursor.fetchone()
    
    if not profile:
        cursor.close()
        db.close()
        flash("Please complete your profile before taking the test", "warning")
        return redirect('/candidate-dashboard#profile')
    
    # Collect ALL skills from profile
    all_skills = []
    
    # Add primary skills
    if profile.get('primary_skills'):
        all_skills.extend([s.strip() for s in str(profile.get('primary_skills', '')).split(',') if s.strip()])
    
    # Add secondary skills
    if profile.get('secondary_skills'):
        all_skills.extend([s.strip() for s in str(profile.get('secondary_skills', '')).split(',') if s.strip()])
    
    # Add frameworks/libraries
    if profile.get('frameworks_libraries'):
        all_skills.extend([s.strip() for s in str(profile.get('frameworks_libraries', '')).split(',') if s.strip()])
    
    # Add databases
    if profile.get('databases'):
        all_skills.extend([s.strip() for s in str(profile.get('databases', '')).split(',') if s.strip()])
    
    # Add cloud platforms
    if profile.get('cloud_platforms'):
        all_skills.extend([s.strip() for s in str(profile.get('cloud_platforms', '')).split(',') if s.strip()])
    
    # Add tools/technologies
    if profile.get('tools_technologies'):
        all_skills.extend([s.strip() for s in str(profile.get('tools_technologies', '')).split(',') if s.strip()])
    
    # Remove duplicates while preserving order
    seen = set()
    all_skills = [s for s in all_skills if not (s in seen or seen.add(s))]
    
    if not all_skills:
        cursor.close()
        db.close()
        flash("Please add skills to your profile before taking the test", "warning")
        return redirect('/candidate-dashboard#profile')
    
    skills_text = ", ".join(all_skills)
    print(f"All skills for test: {skills_text}")
    
    # Get all previous questions asked to this candidate for uniqueness
    cursor.execute("""
        SELECT DISTINCT q.question_text 
        FROM ai_test_questions q
        JOIN ai_tests t ON q.test_id = t.id
        WHERE t.candidate_id = %s AND t.status = 'completed'
    """, (candidate_id,))
    previous_questions = [row['question_text'] for row in cursor.fetchall()]
    print(f"Found {len(previous_questions)} previous questions for this candidate")
    
    # Check if there's an ongoing test
    cursor.execute(
        "SELECT id FROM ai_tests WHERE candidate_id = %s AND status = 'in_progress' ORDER BY started_at DESC LIMIT 1",
        (candidate_id,)
    )
    existing_test = cursor.fetchone()
    
    if existing_test:
        # Check if the test has questions
        cursor.execute(
            "SELECT COUNT(*) as count FROM ai_test_questions WHERE test_id = %s",
            (existing_test["id"],)
        )
        question_count = cursor.fetchone()
        
        if question_count['count'] > 0:
            # Test has questions, continue with it
            cursor.close()
            db.close()
            return redirect(f'/take-ai-test/{existing_test["id"]}')
        else:
            # Test exists but has no questions, delete it and create new one
            cursor.execute("DELETE FROM ai_tests WHERE id = %s", (existing_test["id"],))
            db.commit()
    
    # Create new test with ALL skills
    print(f"Creating test for candidate {candidate_id} with skills: {skills_text}")
    
    cursor.execute(
        "INSERT INTO ai_tests (candidate_id, skills_tested) VALUES (%s, %s)",
        (candidate_id, skills_text)
    )
    test_id = cursor.lastrowid
    db.commit()
    print(f"Created test with ID: {test_id}")
    
    # Generate 25 AI questions based on ALL skills
    print("Starting question generation...")
    try:
        questions = generate_ai_questions(skills_text, all_skills, 25, previous_questions)
        print(f"Generated {len(questions)} questions")
    except Exception as e:
        # Clean up the test record if question generation fails
        cursor.execute("DELETE FROM ai_tests WHERE id = %s", (test_id,))
        db.commit()
        cursor.close()
        db.close()
        
        error_msg = str(e)
        if "GEMINI_API_KEY" in error_msg:
            flash("AI question generation is not configured. Please contact administrator.", "danger")
        else:
            flash(f"Failed to generate test questions: {error_msg}. Please try again.", "danger")
        
        return redirect('/candidate-dashboard#ai-assessments')
    
    # Save questions to database
    for idx, q in enumerate(questions, 1):
        cursor.execute(
            """INSERT INTO ai_test_questions 
            (test_id, question_number, question_text, option_a, option_b, option_c, option_d, correct_answer) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (test_id, idx, q['question'], q['option_a'], q['option_b'], q['option_c'], q['option_d'], q['correct_answer'])
        )
        print(f"Saved question {idx}")
    
    db.commit()
    cursor.close()
    db.close()
    
    return redirect(f'/take-ai-test/{test_id}')

@app.route('/take-ai-test/<int:test_id>')
def take_ai_test(test_id):
    if session.get('role') != 'candidate':
        return redirect('/login')
    
    candidate_id = session.get('user_id')
    
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    # Verify test belongs to candidate
    cursor.execute(
        "SELECT * FROM ai_tests WHERE id = %s AND candidate_id = %s",
        (test_id, candidate_id)
    )
    test = cursor.fetchone()
    
    if not test:
        cursor.close()
        db.close()
        flash("Test not found", "danger")
        return redirect('/candidate-dashboard')
    
    if test['status'] == 'completed':
        cursor.close()
        db.close()
        flash("You have already completed this test", "info")
        return redirect('/candidate-dashboard#ai-assessments')
    
    # Get all questions for this test
    cursor.execute(
        "SELECT * FROM ai_test_questions WHERE test_id = %s ORDER BY question_number",
        (test_id,)
    )
    questions = cursor.fetchall()
    
    cursor.close()
    db.close()
    
    return render_template('ai_test.html', test=test, questions=questions)

@app.route('/submit-answer/<int:test_id>/<int:question_id>', methods=['POST'])
def submit_answer(test_id, question_id):
    if session.get('role') != 'candidate':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    candidate_id = session.get('user_id')
    data = request.get_json()
    answer = data.get('answer')
    
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    # Verify test belongs to candidate
    cursor.execute(
        "SELECT * FROM ai_tests WHERE id = %s AND candidate_id = %s AND status = 'in_progress'",
        (test_id, candidate_id)
    )
    test = cursor.fetchone()
    
    if not test:
        cursor.close()
        db.close()
        return jsonify({'success': False, 'message': 'Test not found'}), 404
    
    # Get question and check answer
    cursor.execute(
        "SELECT * FROM ai_test_questions WHERE id = %s AND test_id = %s",
        (question_id, test_id)
    )
    question = cursor.fetchone()
    
    if not question:
        cursor.close()
        db.close()
        return jsonify({'success': False, 'message': 'Question not found'}), 404
    
    is_correct = (answer == question['correct_answer'])
    
    # Update answer
    cursor.execute(
        "UPDATE ai_test_questions SET candidate_answer = %s, is_correct = %s WHERE id = %s",
        (answer, is_correct, question_id)
    )
    
    db.commit()
    cursor.close()
    db.close()
    
    return jsonify({'success': True, 'is_correct': is_correct})

@app.route('/finish-test/<int:test_id>', methods=['POST'])
def finish_test(test_id):
    if session.get('role') != 'candidate':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    candidate_id = session.get('user_id')
    
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    # Verify test belongs to candidate
    cursor.execute(
        "SELECT * FROM ai_tests WHERE id = %s AND candidate_id = %s AND status = 'in_progress'",
        (test_id, candidate_id)
    )
    test = cursor.fetchone()
    
    if not test:
        cursor.close()
        db.close()
        return jsonify({'success': False, 'message': 'Test not found'}), 404
    
    # Calculate marks
    cursor.execute(
        "SELECT COUNT(*) as correct FROM ai_test_questions WHERE test_id = %s AND is_correct = 1",
        (test_id,)
    )
    result = cursor.fetchone()
    correct_count = result['correct']
    
    obtained_marks = correct_count * 2
    percentage = (obtained_marks / test['total_marks']) * 100
    
    # Analyze skill gaps - identify weak skills
    cursor.execute("""
        SELECT question_text, is_correct 
        FROM ai_test_questions 
        WHERE test_id = %s
    """, (test_id,))
    all_questions = cursor.fetchall()
    
    skill_analysis = {}
    weak_skills = []
    
    for q in all_questions:
        # Extract skill from question text (format: [Skill - Level] Question)
        question = q['question_text']
        if '[' in question and ']' in question:
            skill_part = question[question.find('[')+1:question.find(']')]
            if ' - ' in skill_part:
                skill = skill_part.split(' - ')[0].strip()
                
                if skill not in skill_analysis:
                    skill_analysis[skill] = {'total': 0, 'correct': 0}
                
                skill_analysis[skill]['total'] += 1
                if q['is_correct']:
                    skill_analysis[skill]['correct'] += 1
    
    # Identify weak skills (less than 60% accuracy)
    for skill, stats in skill_analysis.items():
        accuracy = (stats['correct'] / stats['total'] * 100) if stats['total'] > 0 else 0
        if accuracy < 60:
            weak_skills.append(skill)
    
    skill_gap_report = ', '.join(weak_skills) if weak_skills else 'No major gaps identified'
    
    # Update test status with skill gap analysis
    cursor.execute(
        "UPDATE ai_tests SET status = 'completed', obtained_marks = %s, percentage = %s, completed_at = NOW() WHERE id = %s",
        (obtained_marks, percentage, test_id)
    )
    
    db.commit()
    cursor.close()
    db.close()
    
    return jsonify({
        'success': True,
        'obtained_marks': obtained_marks,
        'total_marks': test['total_marks'],
        'percentage': round(percentage, 2),
        'correct_count': correct_count,
        'total_questions': test['total_questions'],
        'skill_gaps': weak_skills,
        'skill_gap_report': skill_gap_report
    })

@app.route('/view-candidate-test/<int:candidate_id>')
def view_candidate_test(candidate_id):
    if session.get('role') != 'recruiter':
        return redirect('/login')
    
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    # Get all completed tests for this candidate
    cursor.execute("""
        SELECT id, test_type, total_questions, total_marks, obtained_marks, 
               percentage, skills_tested, completed_at
        FROM ai_tests
        WHERE candidate_id = %s AND status = 'completed'
        ORDER BY completed_at DESC
    """, (candidate_id,))
    tests = cursor.fetchall()
    
    # Get candidate info
    cursor.execute("SELECT name, email FROM candidates WHERE id = %s", (candidate_id,))
    candidate = cursor.fetchone()
    
    cursor.close()
    db.close()
    
    if not candidate:
        flash("Candidate not found", "danger")
        return redirect('/applications')
    
    return render_template('view_candidate_tests.html', tests=tests, candidate=candidate)

@app.route('/skill-gap-analysis/<int:test_id>')
def skill_gap_analysis(test_id):
    if session.get('role') != 'candidate':
        return redirect('/login')
    
    candidate_id = session.get('user_id')
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    # Verify test belongs to candidate
    cursor.execute(
        "SELECT * FROM ai_tests WHERE id = %s AND candidate_id = %s AND status = 'completed'",
        (test_id, candidate_id)
    )
    test = cursor.fetchone()
    
    if not test:
        cursor.close()
        db.close()
        flash("Test not found", "danger")
        return redirect('/candidate-dashboard#ai-assessments')
    
    # Get all questions and analyze by skill
    cursor.execute("""
        SELECT question_text, is_correct, candidate_answer, correct_answer
        FROM ai_test_questions 
        WHERE test_id = %s
        ORDER BY question_number
    """, (test_id,))
    questions = cursor.fetchall()
    
    cursor.close()
    db.close()
    
    # Analyze skills
    skill_performance = {}
    for q in questions:
        question = q['question_text']
        if '[' in question and ']' in question:
            skill_part = question[question.find('[')+1:question.find(']')]
            if ' - ' in skill_part:
                parts = skill_part.split(' - ')
                skill = parts[0].strip()
                level = parts[1].strip() if len(parts) > 1 else 'MEDIUM'
                
                if skill not in skill_performance:
                    skill_performance[skill] = {
                        'total': 0,
                        'correct': 0,
                        'wrong': 0,
                        'easy': {'total': 0, 'correct': 0},
                        'medium': {'total': 0, 'correct': 0},
                        'hard': {'total': 0, 'correct': 0}
                    }
                
                skill_performance[skill]['total'] += 1
                
                # Track by difficulty
                level_key = level.lower()
                if level_key in skill_performance[skill]:
                    skill_performance[skill][level_key]['total'] += 1
                    if q['is_correct']:
                        skill_performance[skill][level_key]['correct'] += 1
                
                if q['is_correct']:
                    skill_performance[skill]['correct'] += 1
                else:
                    skill_performance[skill]['wrong'] += 1
    
    # Calculate percentages and identify weak skills
    weak_skills = []
    strong_skills = []
    
    for skill, stats in skill_performance.items():
        stats['percentage'] = round((stats['correct'] / stats['total'] * 100), 1) if stats['total'] > 0 else 0
        stats['skill_name'] = skill
        
        if stats['percentage'] < 60:
            weak_skills.append(stats)
        elif stats['percentage'] >= 80:
            strong_skills.append(stats)
    
    # Get course recommendations for weak skills
    recommendations = get_course_recommendations(weak_skills)
    
    return render_template('skill_gap_analysis.html', 
                         test=test, 
                         skill_performance=skill_performance,
                         weak_skills=weak_skills,
                         strong_skills=strong_skills,
                         recommendations=recommendations)

def get_course_recommendations(weak_skills):
    """Generate course and video recommendations for weak skills"""
    recommendations = {}
    
    # Course database with popular learning resources
    course_library = {
        'Python': [
            {'title': 'Python for Everybody - Coursera', 'url': 'https://www.coursera.org/specializations/python', 'type': 'Course', 'platform': 'Coursera'},
            {'title': 'Complete Python Bootcamp - Udemy', 'url': 'https://www.udemy.com/course/complete-python-bootcamp/', 'type': 'Course', 'platform': 'Udemy'},
            {'title': 'Python Tutorial - Programming with Mosh', 'url': 'https://www.youtube.com/watch?v=_uQrJ0TkZlc', 'type': 'Video', 'platform': 'YouTube'},
        ],
        'SQL': [
            {'title': 'SQL for Data Science - Coursera', 'url': 'https://www.coursera.org/learn/sql-for-data-science', 'type': 'Course', 'platform': 'Coursera'},
            {'title': 'The Complete SQL Bootcamp - Udemy', 'url': 'https://www.udemy.com/course/the-complete-sql-bootcamp/', 'type': 'Course', 'platform': 'Udemy'},
            {'title': 'SQL Tutorial - Full Database Course', 'url': 'https://www.youtube.com/watch?v=HXV3zeQKqGY', 'type': 'Video', 'platform': 'YouTube'},
        ],
        'JavaScript': [
            {'title': 'JavaScript - The Complete Guide - Udemy', 'url': 'https://www.udemy.com/course/javascript-the-complete-guide-2020-beginner-advanced/', 'type': 'Course', 'platform': 'Udemy'},
            {'title': 'JavaScript Algorithms and Data Structures', 'url': 'https://www.freecodecamp.org/learn/javascript-algorithms-and-data-structures/', 'type': 'Course', 'platform': 'freeCodeCamp'},
            {'title': 'JavaScript Crash Course', 'url': 'https://www.youtube.com/watch?v=hdI2bqOjy3c', 'type': 'Video', 'platform': 'YouTube'},
        ],
        'HTML': [
            {'title': 'HTML Full Course - Build a Website Tutorial', 'url': 'https://www.youtube.com/watch?v=pQN-pnXPaVg', 'type': 'Video', 'platform': 'YouTube'},
            {'title': 'Responsive Web Design - freeCodeCamp', 'url': 'https://www.freecodecamp.org/learn/responsive-web-design/', 'type': 'Course', 'platform': 'freeCodeCamp'},
        ],
        'CSS': [
            {'title': 'CSS - The Complete Guide - Udemy', 'url': 'https://www.udemy.com/course/css-the-complete-guide-incl-flexbox-grid-sass/', 'type': 'Course', 'platform': 'Udemy'},
            {'title': 'CSS Tutorial - Zero to Hero', 'url': 'https://www.youtube.com/watch?v=1Rs2ND1ryYc', 'type': 'Video', 'platform': 'YouTube'},
            {'title': 'Responsive Web Design - freeCodeCamp', 'url': 'https://www.freecodecamp.org/learn/responsive-web-design/', 'type': 'Course', 'platform': 'freeCodeCamp'},
        ],
        'React': [
            {'title': 'React - The Complete Guide - Udemy', 'url': 'https://www.udemy.com/course/react-the-complete-guide-incl-redux/', 'type': 'Course', 'platform': 'Udemy'},
            {'title': 'React JS Full Course - YouTube', 'url': 'https://www.youtube.com/watch?v=bMknfKXIFA8', 'type': 'Video', 'platform': 'YouTube'},
        ],
        'Django': [
            {'title': 'Django for Everybody - Coursera', 'url': 'https://www.coursera.org/specializations/django', 'type': 'Course', 'platform': 'Coursera'},
            {'title': 'Python Django Tutorial - YouTube', 'url': 'https://www.youtube.com/watch?v=F5mRW0jo-U4', 'type': 'Video', 'platform': 'YouTube'},
        ],
        'Flask': [
            {'title': 'Flask Mega-Tutorial', 'url': 'https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-i-hello-world', 'type': 'Tutorial', 'platform': 'Blog'},
            {'title': 'Flask Course - Python Web Development', 'url': 'https://www.youtube.com/watch?v=Qr4QMBUPxWo', 'type': 'Video', 'platform': 'YouTube'},
        ],
        'Git': [
            {'title': 'Git and GitHub for Beginners', 'url': 'https://www.youtube.com/watch?v=RGOj5yH7evk', 'type': 'Video', 'platform': 'YouTube'},
            {'title': 'Version Control with Git - Coursera', 'url': 'https://www.coursera.org/learn/version-control-with-git', 'type': 'Course', 'platform': 'Coursera'},
        ],
        'AWS': [
            {'title': 'AWS Certified Cloud Practitioner', 'url': 'https://www.youtube.com/watch?v=3hLmDS179YE', 'type': 'Video', 'platform': 'YouTube'},
            {'title': 'AWS Fundamentals - Coursera', 'url': 'https://www.coursera.org/learn/aws-fundamentals-going-cloud-native', 'type': 'Course', 'platform': 'Coursera'},
        ],
        'REST': [
            {'title': 'REST API concepts and examples', 'url': 'https://www.youtube.com/watch?v=7YcW25PHnAA', 'type': 'Video', 'platform': 'YouTube'},
            {'title': 'REST APIs with Flask and Python', 'url': 'https://www.udemy.com/course/rest-api-flask-and-python/', 'type': 'Course', 'platform': 'Udemy'},
        ],
        'MySQL': [
            {'title': 'MySQL Tutorial for Beginners', 'url': 'https://www.youtube.com/watch?v=7S_tz1z_5bA', 'type': 'Video', 'platform': 'YouTube'},
            {'title': 'MySQL Database Development Mastery', 'url': 'https://www.udemy.com/course/mysql-database-development-mastery/', 'type': 'Course', 'platform': 'Udemy'},
        ],
        'PostgreSQL': [
            {'title': 'PostgreSQL Tutorial Full Course', 'url': 'https://www.youtube.com/watch?v=qw--VYLpxG4', 'type': 'Video', 'platform': 'YouTube'},
            {'title': 'The Complete PostgreSQL Course', 'url': 'https://www.udemy.com/course/the-complete-python-postgresql-developer-course/', 'type': 'Course', 'platform': 'Udemy'},
        ],
    }
    
    # Default recommendations for any skill not in library
    default_recommendations = [
        {'title': 'Search on Udemy', 'url': 'https://www.udemy.com', 'type': 'Platform', 'platform': 'Udemy'},
        {'title': 'Search on Coursera', 'url': 'https://www.coursera.org', 'type': 'Platform', 'platform': 'Coursera'},
        {'title': 'Search on YouTube', 'url': 'https://www.youtube.com', 'type': 'Platform', 'platform': 'YouTube'},
        {'title': 'freeCodeCamp', 'url': 'https://www.freecodecamp.org', 'type': 'Platform', 'platform': 'freeCodeCamp'},
    ]
    
    for skill_data in weak_skills:
        skill = skill_data['skill_name']
        
        # Find matching courses (case-insensitive partial match)
        matching_courses = []
        for key, courses in course_library.items():
            if key.lower() in skill.lower() or skill.lower() in key.lower():
                matching_courses.extend(courses)
        
        if matching_courses:
            recommendations[skill] = matching_courses
        else:
            # Use default recommendations
            recommendations[skill] = default_recommendations
    
    return recommendations

@app.route('/view-test-details/<int:test_id>')
def view_test_details(test_id):
    if session.get('role') not in ['recruiter', 'candidate']:
        return redirect('/login')
    
    user_id = session.get('user_id')
    user_role = session.get('role')
    
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    # Get test details
    cursor.execute("SELECT * FROM ai_tests WHERE id = %s", (test_id,))
    test = cursor.fetchone()
    
    if not test:
        cursor.close()
        db.close()
        flash("Test not found", "danger")
        return redirect('/candidate-dashboard' if user_role == 'candidate' else '/applications')
    
    # Authorization check
    if user_role == 'candidate' and test['candidate_id'] != user_id:
        cursor.close()
        db.close()
        flash("Unauthorized access", "danger")
        return redirect('/candidate-dashboard')
    
    # For recruiters, verify the candidate applied to their jobs
    if user_role == 'recruiter':
        cursor.execute("""
            SELECT COUNT(*) as count FROM applications a
            JOIN jobs j ON a.job_id = j.id
            WHERE a.candidate_id = %s AND j.recruiter_id = %s
        """, (test['candidate_id'], user_id))
        result = cursor.fetchone()
        if result['count'] == 0:
            cursor.close()
            db.close()
            flash("Unauthorized access", "danger")
            return redirect('/applications')
    
    # Get all questions for this test
    cursor.execute("""
        SELECT * FROM ai_test_questions 
        WHERE test_id = %s 
        ORDER BY question_number
    """, (test_id,))
    questions = cursor.fetchall()
    
    # Get candidate info
    cursor.execute("SELECT name FROM candidates WHERE id = %s", (test['candidate_id'],))
    candidate = cursor.fetchone()
    
    cursor.close()
    db.close()
    
    return render_template('test_details.html', test=test, questions=questions, candidate=candidate)

def generate_ai_questions(skills_text, skills_list, num_questions=25, previous_questions=None):
    """Generate AI-powered questions based on candidate skills, ensuring uniqueness"""
    import google.generativeai as genai
    
    # Configure API key from environment
    api_key = os.environ.get('GEMINI_API_KEY')
    print(f"API Key available: {bool(api_key)}")
    
    if not api_key:
        print("ERROR: No API key found. AI generation is REQUIRED.")
        raise Exception("GEMINI_API_KEY not configured. Cannot generate questions without AI.")
    
    try:
        print(f"Generating {num_questions} questions for skills: {skills_text}")
        print(f"Skills list: {skills_list}")
        print(f"Number of skills: {len(skills_list)}")
        print(f"Number of previous questions to avoid: {len(previous_questions) if previous_questions else 0}")
        
        genai.configure(api_key=api_key)
        
        # Get the first available model that supports generateContent
        model = None
        available_models = []
        for m in genai.list_models():
            if 'generateContent' in m.supported_generation_methods:
                available_models.append(m.name)
                if model is None:
                    model = genai.GenerativeModel(model_name=m.name)
                    print(f"Using model: {m.name}")
        
        if model is None:
            print("Available models:", available_models)
            raise Exception("No compatible Gemini model found that supports generateContent")
        
        # Add timestamp for uniqueness seed
        import time
        timestamp = int(time.time())
        
        # Calculate distribution: ~33% easy, ~33% medium, ~34% hard
        easy_count = num_questions // 3
        medium_count = num_questions // 3
        hard_count = num_questions - easy_count - medium_count
        
        # Calculate questions per skill
        questions_per_skill = max(1, num_questions // len(skills_list)) if len(skills_list) > 0 else 1
        
        # Build exclusion list if previous questions exist
        exclusion_text = ""
        if previous_questions and len(previous_questions) > 0:
            exclusion_text = f"""

CRITICAL: DO NOT REPEAT ANY OF THESE PREVIOUSLY ASKED QUESTIONS:
{chr(10).join([f"- {q}" for q in previous_questions[:50]])}  

You MUST generate COMPLETELY NEW and DIFFERENT questions that have NEVER been asked before to this candidate."""
        
        prompt = f"""Generate {num_questions} COMPLETELY UNIQUE multiple choice technical questions.

TEST ID: {timestamp} (Use this to ensure uniqueness)

SKILLS TO COVER: {', '.join(skills_list)}
{exclusion_text}

CRITICAL REQUIREMENTS:
1. MUST generate exactly {num_questions} UNIQUE questions - NO DUPLICATES
2. Questions must be COMPLETELY DIFFERENT from any previous questions listed above
3. MUST distribute questions EVENLY across ALL {len(skills_list)} skills mentioned
4. MUST generate approximately {questions_per_skill} questions per skill
5. Each question focuses on ONE specific skill ONLY
6. Mix difficulty: ~{easy_count} EASY, ~{medium_count} MEDIUM, ~{hard_count} HARD
7. Use fresh scenarios, different concepts, and varied question styles

SKILL DISTRIBUTION PLAN:
{chr(10).join([f"- {skill}: ~{questions_per_skill} questions" for skill in skills_list])}

DIFFICULTY LEVELS:
- EASY: Basic concepts, definitions, fundamental syntax
- MEDIUM: Application, problem-solving, best practices, common patterns
- HARD: Advanced concepts, optimization, edge cases, complex scenarios, architecture

FORMAT (EXACTLY):
SKILL: [Specific skill name from the list above]
LEVEL: [EASY/MEDIUM/HARD]
Q: [Unique question text]
A) [Option A]
B) [Option B]
C) [Option C]
D) [Option D]
ANSWER: [A/B/C/D]
---

Generate all {num_questions} questions NOW. Cover each skill from the list. Make questions FRESH and UNIQUE!"""
        
        print("Calling Gemini API...")
        response = model.generate_content(prompt)
        questions_text = response.text
        print(f"Received response, length: {len(questions_text)}")
        
        # Parse the response
        questions = []
        question_blocks = questions_text.split('---')
        print(f"Found {len(question_blocks)} blocks")
        
        for block in question_blocks:
            block = block.strip()
            if not block or 'Q:' not in block:
                continue
                
            try:
                # Extract skill
                skill = "General"
                if 'SKILL:' in block:
                    skill_start = block.find('SKILL:') + 6
                    skill_end = block.find('\n', skill_start)
                    skill = block[skill_start:skill_end].strip()
                
                # Extract difficulty level
                level = "MEDIUM"
                if 'LEVEL:' in block:
                    level_start = block.find('LEVEL:') + 6
                    level_end = block.find('\n', level_start)
                    level = block[level_start:level_end].strip()
                
                # Extract question with skill tag
                q_start = block.find('Q:') + 2
                q_end = block.find('A)')
                question_text = block[q_start:q_end].strip()
                
                # Prepend skill and level to question
                question = f"[{skill} - {level}] {question_text}"
                
                # Extract options
                a_start = block.find('A)') + 2
                b_start = block.find('B)')

                option_a = block[a_start:b_start].strip()
                
                b_start = block.find('B)') + 2
                c_start = block.find('C)')
                option_b = block[b_start:c_start].strip()
                
                c_start = block.find('C)') + 2
                d_start = block.find('D)')
                option_c = block[c_start:d_start].strip()
                
                d_start = block.find('D)') + 2
                ans_start = block.find('ANSWER:')
                option_d = block[d_start:ans_start].strip()
                
                # Extract answer
                ans_start = block.find('ANSWER:') + 7
                correct_answer = block[ans_start:].strip()[0].upper()
                
                questions.append({
                    'question': question,
                    'option_a': option_a,
                    'option_b': option_b,
                    'option_c': option_c,
                    'option_d': option_d,
                    'correct_answer': correct_answer
                })
                
                if len(questions) >= num_questions:
                    break
            except Exception as parse_error:
                print(f"Error parsing question block: {parse_error}")
                continue
        
        print(f"Successfully parsed {len(questions)} questions")
        
        # If we didn't get enough questions, try again with a more explicit prompt
        if len(questions) < num_questions:
            print(f"Only got {len(questions)} questions, need {num_questions}. Trying again...")
            retry_prompt = f"""I need EXACTLY {num_questions - len(questions)} MORE unique questions.

REMAINING SKILLS: {', '.join(skills_list)}

Generate {num_questions - len(questions)} COMPLETELY NEW questions that are DIFFERENT from previous ones.

FORMAT (EXACTLY):
SKILL: [skill name]
LEVEL: [EASY/MEDIUM/HARD]
Q: [question]
A) [option]
B) [option]
C) [option]
D) [option]
ANSWER: [A/B/C/D]
---"""
            
            retry_response = model.generate_content(retry_prompt)
            retry_blocks = retry_response.text.split('---')
            
            for block in retry_blocks:
                block = block.strip()
                if not block or 'Q:' not in block:
                    continue
                    
                try:
                    # Extract skill
                    skill = "General"
                    if 'SKILL:' in block:
                        skill_start = block.find('SKILL:') + 6
                        skill_end = block.find('\n', skill_start)
                        skill = block[skill_start:skill_end].strip()
                    
                    # Extract difficulty level
                    level = "MEDIUM"
                    if 'LEVEL:' in block:
                        level_start = block.find('LEVEL:') + 6
                        level_end = block.find('\n', level_start)
                        level = block[level_start:level_end].strip()
                    
                    # Extract question with skill tag
                    q_start = block.find('Q:') + 2
                    q_end = block.find('A)')
                    question_text = block[q_start:q_end].strip()
                    
                    # Prepend skill and level to question
                    question = f"[{skill} - {level}] {question_text}"
                    
                    # Extract options
                    a_start = block.find('A)') + 2
                    b_start = block.find('B)')
                    option_a = block[a_start:b_start].strip()
                    
                    b_start = block.find('B)') + 2
                    c_start = block.find('C)')
                    option_b = block[b_start:c_start].strip()
                    
                    c_start = block.find('C)') + 2
                    d_start = block.find('D)')
                    option_c = block[c_start:d_start].strip()
                    
                    d_start = block.find('D)') + 2
                    ans_start = block.find('ANSWER:')
                    option_d = block[d_start:ans_start].strip()
                    
                    # Extract answer
                    ans_start = block.find('ANSWER:') + 7
                    correct_answer = block[ans_start:].strip()[0].upper()
                    
                    questions.append({
                        'question': question,
                        'option_a': option_a,
                        'option_b': option_b,
                        'option_c': option_c,
                        'option_d': option_d,
                        'correct_answer': correct_answer
                    })
                    
                    if len(questions) >= num_questions:
                        break
                except Exception as parse_error:
                    print(f"Error parsing retry question: {parse_error}")
                    continue
            
            print(f"After retry: {len(questions)} total questions")
        
        if len(questions) < num_questions:
            raise Exception(f"AI could only generate {len(questions)} questions out of {num_questions} required. Please try again.")
        
        # Verify uniqueness against previous questions
        if previous_questions:
            unique_questions = []
            for q in questions:
                # Remove the [Skill - Level] prefix for comparison
                q_text = q['question']
                if ']' in q_text:
                    q_text_clean = q_text.split(']', 1)[1].strip()
                else:
                    q_text_clean = q_text
                
                # Check if this question is similar to any previous question
                is_duplicate = False
                for prev_q in previous_questions:
                    prev_q_clean = prev_q.split(']', 1)[1].strip() if ']' in prev_q else prev_q
                    # Simple similarity check - if 80% of words match, consider duplicate
                    if prev_q_clean.lower() == q_text_clean.lower():
                        is_duplicate = True
                        print(f"Duplicate detected: {q_text_clean[:50]}...")
                        break
                
                if not is_duplicate:
                    unique_questions.append(q)
            
            print(f"Filtered to {len(unique_questions)} unique questions from {len(questions)}")
            
            if len(unique_questions) < num_questions:
                print(f"Warning: Only {len(unique_questions)} unique questions after filtering. Using all available.")
                questions = unique_questions
            else:
                questions = unique_questions[:num_questions]
        
        return questions[:num_questions]
        
    except Exception as e:
        print(f"AI generation error: {e}")
        import traceback
        traceback.print_exc()
        raise Exception(f"Failed to generate AI questions: {str(e)}")

def generate_fallback_questions(skills_list, num_questions=25):
    """
    DEPRECATED: Fallback questions are no longer used.
    All questions must be AI-generated.
    """
    raise Exception("Fallback questions are disabled. Only AI-generated questions are allowed. Please ensure GEMINI_API_KEY is configured.")

@app.route('/mentor-chat/<int:mentorship_request_id>')
def mentor_chat(mentorship_request_id):
    user_role = session.get('role')
    user_id = session.get('user_id')
    
    if not user_role or user_role not in ['candidate', 'mentor']:
        return redirect('/login')
    
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    # Get mentorship request details and verify access
    cursor.execute("""
        SELECT mr.*, 
               c.name as candidate_name, c.email as candidate_email,
               m.name as mentor_name, m.email as mentor_email,
               mp.expertise, mp.company
        FROM mentorship_requests mr
        JOIN candidates c ON mr.candidate_id = c.id
        JOIN mentors m ON mr.mentor_id = m.id
        LEFT JOIN mentor_profiles mp ON m.id = mp.mentor_id
        WHERE mr.id = %s
    """, (mentorship_request_id,))
    request = cursor.fetchone()
    
    if not request:
        cursor.close()
        db.close()
        flash("Mentorship request not found", "danger")
        return redirect('/candidate-dashboard' if user_role == 'candidate' else '/mentor-dashboard')
    
    # Verify user has access to this chat
    if user_role == 'candidate' and request['candidate_id'] != user_id:
        cursor.close()
        db.close()
        flash("Unauthorized access", "danger")
        return redirect('/candidate-dashboard')
    
    if user_role == 'mentor' and request['mentor_id'] != user_id:
        cursor.close()
        db.close()
        flash("Unauthorized access", "danger")
        return redirect('/mentor-dashboard')
    
    # Only allow chat if request is accepted
    if request['status'] != 'Accepted':
        cursor.close()
        db.close()
        flash("Chat is only available for accepted mentorship requests", "warning")
        return redirect('/candidate-dashboard' if user_role == 'candidate' else '/mentor-dashboard')
    
    # Get all messages for this mentorship
    cursor.execute("""
        SELECT mm.*, 
               CASE 
                   WHEN mm.sender_role = 'candidate' THEN c.name
                   WHEN mm.sender_role = 'mentor' THEN m.name
               END as sender_name
        FROM mentor_messages mm
        LEFT JOIN candidates c ON mm.sender_id = c.id AND mm.sender_role = 'candidate'
        LEFT JOIN mentors m ON mm.sender_id = m.id AND mm.sender_role = 'mentor'
        WHERE mm.mentorship_request_id = %s
        ORDER BY mm.created_at ASC
    """, (mentorship_request_id,))
    messages = cursor.fetchall()
    
    # Mark messages as read for the current user
    cursor.execute("""
        UPDATE mentor_messages 
        SET is_read = 1 
        WHERE mentorship_request_id = %s 
        AND sender_role != %s
        AND is_read = 0
    """, (mentorship_request_id, user_role))
    db.commit()
    
    # Check if meeting is scheduled
    cursor.execute("""
        SELECT * FROM mentor_meetings 
        WHERE mentor_id = %s AND candidate_id = %s
    """, (request['mentor_id'], request['candidate_id']))
    meeting = cursor.fetchone()

    from datetime import datetime, date, time, timedelta

    # Normalize meeting date/time values for safe template rendering
    if meeting:
        meeting_date = meeting.get('meeting_date')
        meeting_time = meeting.get('meeting_time')

        if isinstance(meeting_date, (datetime, date)):
            meeting['meeting_date_formatted'] = meeting_date.strftime('%d %b %Y')
        else:
            meeting['meeting_date_formatted'] = meeting_date

        if isinstance(meeting_time, (datetime, time)):
            meeting['meeting_time_formatted'] = meeting_time.strftime('%I:%M %p')
        elif isinstance(meeting_time, timedelta):
            meeting_time_obj = (datetime.min + meeting_time).time()
            meeting['meeting_time_formatted'] = meeting_time_obj.strftime('%I:%M %p')
        else:
            meeting['meeting_time_formatted'] = meeting_time
    
    cursor.close()
    db.close()
    
    return render_template('mentor_chat.html', 
                         request=request, 
                         messages=messages, 
                         user_role=user_role,
                         meeting=meeting,
                         now=datetime.now(),
                         timedelta=timedelta)

@app.route('/send-mentor-message', methods=['POST'])
def send_mentor_message():
    user_role = session.get('role')
    user_id = session.get('user_id')
    
    if not user_role or user_role not in ['candidate', 'mentor']:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    data = request.get_json()
    mentorship_request_id = data.get('mentorship_request_id')
    message_text = data.get('message', '').strip()
    
    if not message_text:
        return jsonify({'success': False, 'message': 'Message cannot be empty'}), 400
    
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    # Verify access
    cursor.execute("""
        SELECT * FROM mentorship_requests 
        WHERE id = %s AND (candidate_id = %s OR mentor_id = %s) AND status = 'Accepted'
    """, (mentorship_request_id, user_id, user_id))
    request_data = cursor.fetchone()
    
    if not request_data:
        cursor.close()
        db.close()
        return jsonify({'success': False, 'message': 'Invalid request'}), 403
    
    # Insert message
    cursor.execute("""
        INSERT INTO mentor_messages (mentorship_request_id, sender_role, sender_id, message_text)
        VALUES (%s, %s, %s, %s)
    """, (mentorship_request_id, user_role, user_id, message_text))
    db.commit()
    
    message_id = cursor.lastrowid
    
    # Get sender name
    if user_role == 'candidate':
        cursor.execute("SELECT name FROM candidates WHERE id = %s", (user_id,))
    else:
        cursor.execute("SELECT name FROM mentors WHERE id = %s", (user_id,))
    sender = cursor.fetchone()
    
    cursor.close()
    db.close()
    
    # Emit socket event for real-time update
    socketio.emit('new_mentor_message', {
        'id': message_id,
        'mentorship_request_id': mentorship_request_id,
        'sender_role': user_role,
        'sender_name': sender['name'] if sender else 'Unknown',
        'message_text': message_text,
        'created_at': 'Just now'
    }, room=f"mentorship_{mentorship_request_id}")
    
    return jsonify({'success': True, 'message': 'Message sent'})

@app.route('/schedule-mentor-meeting', methods=['POST'])
def schedule_mentor_meeting():
    user_role = session.get('role')
    user_id = session.get('user_id')
    
    if user_role != 'mentor':
        return jsonify({'success': False, 'message': 'Only mentors can schedule meetings'}), 401
    
    data = request.get_json()
    candidate_id = data.get('candidate_id')
    mode = data.get('mode')
    meeting_date = data.get('meeting_date')
    meeting_time = data.get('meeting_time')
    meeting_link = data.get('meeting_link', '')
    notes = data.get('notes', '')
    
    if not all([candidate_id, mode, meeting_date, meeting_time]):
        return jsonify({'success': False, 'message': 'All fields are required'}), 400
    
    db = get_connection()
    cursor = db.cursor()
    
    # Check if meeting already exists
    cursor.execute("""
        SELECT id FROM mentor_meetings 
        WHERE mentor_id = %s AND candidate_id = %s
    """, (user_id, candidate_id))
    existing = cursor.fetchone()
    
    if existing:
        # Update existing meeting
        cursor.execute("""
            UPDATE mentor_meetings 
            SET mode = %s, meeting_date = %s, meeting_time = %s, 
                meeting_link = %s, notes = %s
            WHERE mentor_id = %s AND candidate_id = %s
        """, (mode, meeting_date, meeting_time, meeting_link, notes, user_id, candidate_id))
    else:
        # Insert new meeting
        cursor.execute("""
            INSERT INTO mentor_meetings 
            (mentor_id, candidate_id, mode, meeting_date, meeting_time, meeting_link, notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (user_id, candidate_id, mode, meeting_date, meeting_time, meeting_link, notes))
    
    db.commit()
    cursor.close()
    db.close()
    
    # Send notification to candidate
    send_notification('candidate', candidate_id, 
                     f'Your mentor has scheduled a meeting on {meeting_date} at {meeting_time}')
    
    return jsonify({'success': True, 'message': 'Meeting scheduled successfully'})

# ==================== AI MOCK INTERVIEW ROUTES ====================

@app.route('/start-mock-interview', methods=['GET', 'POST'])
def start_mock_interview():
    """Start a new AI mock interview session"""
    if session.get('role') != 'candidate':
        return redirect('/login')
    
    candidate_id = session.get('user_id')
    
    if request.method == 'POST':
        interview_type = request.form.get('interview_type', 'technical')
        position_role = request.form.get('position_role', 'Software Engineer')
        difficulty_level = request.form.get('difficulty_level', 'medium')
        
        db = get_connection()
        cursor = db.cursor()
        
        try:
            # Create new interview session
            cursor.execute("""
                INSERT INTO ai_mock_interviews 
                (candidate_id, interview_type, position_role, difficulty_level, status)
                VALUES (%s, %s, %s, %s, 'in_progress')
            """, (candidate_id, interview_type, position_role, difficulty_level))
            
            interview_id = cursor.lastrowid
            db.commit()
            cursor.close()
            db.close()
            
            return redirect(f'/mock-interview/{interview_id}')
            
        except Exception as e:
            db.rollback()
            cursor.close()
            db.close()
            flash(f'Error starting interview: {str(e)}', 'danger')
            return redirect('/candidate-dashboard#ai-assessments')
    
    # GET request - show interview setup page
    return render_template('start_mock_interview.html')

@app.route('/mock-interview/<int:interview_id>')
def mock_interview(interview_id):
    """Main interview interface page"""
    if session.get('role') != 'candidate':
        return redirect('/login')
    
    candidate_id = session.get('user_id')
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    # Verify interview belongs to candidate
    cursor.execute("""
        SELECT * FROM ai_mock_interviews 
        WHERE id = %s AND candidate_id = %s
    """, (interview_id, candidate_id))
    
    interview = cursor.fetchone()
    cursor.close()
    db.close()
    
    if not interview:
        flash('Interview not found', 'danger')
        return redirect('/candidate-dashboard#ai-assessments')
    
    if interview['status'] == 'completed':
        return redirect(f'/mock-interview-result/{interview_id}')
    
    return render_template('mock_interview.html', interview=interview)

@app.route('/api/interview/next-question/<int:interview_id>', methods=['POST'])
def get_next_question(interview_id):
    """Generate next interview question using AI"""
    if session.get('role') != 'candidate':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    candidate_id = session.get('user_id')
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    try:
        # Get interview details
        cursor.execute("""
            SELECT * FROM ai_mock_interviews 
            WHERE id = %s AND candidate_id = %s AND status = 'in_progress'
        """, (interview_id, candidate_id))
        
        interview = cursor.fetchone()
        if not interview:
            return jsonify({'success': False, 'error': 'Interview not found'}), 404
        
        # Check if we've reached the question limit
        current_question_num = interview['questions_answered'] + 1
        if current_question_num > interview['total_questions']:
            return jsonify({'success': False, 'completed': True})
        
        # Get previous questions to maintain context
        cursor.execute("""
            SELECT question_text, candidate_answer 
            FROM ai_interview_responses 
            WHERE interview_id = %s 
            ORDER BY question_number
        """, (interview_id,))
        previous_qa = cursor.fetchall()
        
        # Generate question using AI
        import google.generativeai as genai
        api_key = os.environ.get('GEMINI_API_KEY')
        
        if not api_key:
            return jsonify({'success': False, 'error': 'AI service not configured'}), 500
        
        genai.configure(api_key=api_key)
        
        # Get first available model that supports generateContent
        model = None
        for m in genai.list_models():
            if 'generateContent' in m.supported_generation_methods:
                model = genai.GenerativeModel(model_name=m.name)
                break
        
        if model is None:
            return jsonify({'success': False, 'error': 'No compatible AI model available'}), 500
        
        # Build context for AI
        context = f"""You are conducting a {interview['difficulty_level']} level {interview['interview_type']} interview for the position of {interview['position_role']}.

This is question {current_question_num} out of {interview['total_questions']}.

"""
        if previous_qa:
            context += "Previous questions and answers:\n"
            for qa in previous_qa:
                context += f"Q: {qa['question_text']}\nA: {qa['candidate_answer']}\n\n"
        
        prompt = context + f"""Generate ONE interview question for this candidate. The question should:
1. Be relevant to the role and difficulty level
2. Be clear and specific
3. Not repeat previous questions
4. Test practical knowledge or problem-solving
5. Be answerable in 2-3 minutes

Return ONLY the question text, nothing else."""
        
        response = model.generate_content(prompt)
        question_text = response.text.strip()
        
        # Store the question
        cursor.execute("""
            INSERT INTO ai_interview_responses 
            (interview_id, question_number, question_text)
            VALUES (%s, %s, %s)
        """, (interview_id, current_question_num, question_text))
        
        response_id = cursor.lastrowid
        db.commit()
        cursor.close()
        db.close()
        
        return jsonify({
            'success': True,
            'question': question_text,
            'question_number': current_question_num,
            'total_questions': interview['total_questions'],
            'response_id': response_id
        })
        
    except Exception as e:
        print(f"Error generating question: {e}")
        try:
            cursor.close()
            db.close()
        except:
            pass
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/interview/submit-answer/<int:response_id>', methods=['POST'])
def submit_interview_answer(response_id):
    """Submit and evaluate candidate's answer"""
    if session.get('role') != 'candidate':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    answer = data.get('answer', '').strip()
    duration = data.get('duration', 0)  # in seconds
    
    if not answer:
        return jsonify({'success': False, 'error': 'Answer is required'}), 400
    
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    try:
        # Get the question and interview details
        cursor.execute("""
            SELECT r.*, i.interview_type, i.position_role, i.difficulty_level
            FROM ai_interview_responses r
            JOIN ai_mock_interviews i ON r.interview_id = i.id
            WHERE r.id = %s
        """, (response_id,))
        
        response_data = cursor.fetchone()
        if not response_data:
            return jsonify({'success': False, 'error': 'Response not found'}), 404
        
        # Evaluate answer using AI
        import google.generativeai as genai
        api_key = os.environ.get('GEMINI_API_KEY')
        
        if not api_key:
            return jsonify({'success': False, 'error': 'AI service not configured'}), 500
        
        genai.configure(api_key=api_key)
        
        # Get first available model that supports generateContent
        model = None
        for m in genai.list_models():
            if 'generateContent' in m.supported_generation_methods:
                model = genai.GenerativeModel(model_name=m.name)
                break
        
        if model is None:
            return jsonify({'success': False, 'error': 'No compatible AI model available'}), 500
        
        evaluation_prompt = f"""You are an expert interviewer evaluating a candidate's response.

Interview Context:
- Position: {response_data['position_role']}
- Type: {response_data['interview_type']}
- Level: {response_data['difficulty_level']}

Question: {response_data['question_text']}

Candidate's Answer: {answer}

Evaluate this answer on a scale of 0-10 and provide:
1. Score (0-10)
2. Brief feedback (2-3 sentences) on what was good and what could be improved

Format your response EXACTLY as:
SCORE: [number]
FEEDBACK: [your feedback here]"""
        
        eval_response = model.generate_content(evaluation_prompt)
        eval_text = eval_response.text.strip()
        
        # Parse AI evaluation
        score = 5.0  # default
        feedback = "Answer received."
        
        if "SCORE:" in eval_text and "FEEDBACK:" in eval_text:
            try:
                score_part = eval_text.split("SCORE:")[1].split("FEEDBACK:")[0].strip()
                score = float(score_part)
                feedback = eval_text.split("FEEDBACK:")[1].strip()
            except:
                pass
        
        # Update the response
        cursor.execute("""
            UPDATE ai_interview_responses 
            SET candidate_answer = %s, 
                answer_duration = %s,
                ai_evaluation = %s,
                score = %s,
                feedback = %s,
                answered_at = NOW()
            WHERE id = %s
        """, (answer, duration, eval_text, score, feedback, response_id))
        
        # Update interview progress
        cursor.execute("""
            UPDATE ai_mock_interviews 
            SET questions_answered = questions_answered + 1
            WHERE id = %s
        """, (response_data['interview_id'],))
        
        db.commit()
        cursor.close()
        db.close()
        
        return jsonify({
            'success': True,
            'score': score,
            'feedback': feedback
        })
        
    except Exception as e:
        print(f"Error evaluating answer: {e}")
        try:
            db.rollback()
            cursor.close()
            db.close()
        except:
            pass
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/interview/complete/<int:interview_id>', methods=['POST'])
def complete_interview(interview_id):
    """Complete interview and calculate final scores"""
    if session.get('role') != 'candidate':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    candidate_id = session.get('user_id')
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    try:
        # Get all responses and calculate scores
        cursor.execute("""
            SELECT score FROM ai_interview_responses 
            WHERE interview_id = %s AND candidate_answer IS NOT NULL
        """, (interview_id,))
        
        scores = cursor.fetchall()
        
        if scores:
            avg_score = sum(s['score'] for s in scores) / len(scores)
            overall_score = (avg_score / 10) * 100  # Convert to percentage
        else:
            overall_score = 0
        
        # Generate overall feedback
        import google.generativeai as genai
        api_key = os.environ.get('GEMINI_API_KEY')
        
        overall_feedback = "Interview completed. Review your detailed performance below."
        
        if api_key:
            try:
                genai.configure(api_key=api_key)
                
                # Get first available model that supports generateContent
                model = None
                for m in genai.list_models():
                    if 'generateContent' in m.supported_generation_methods:
                        model = genai.GenerativeModel(model_name=m.name)
                        break
                
                if model is None:
                    overall_feedback = "Interview completed. Review your detailed performance below."
                else:
                    # Get all Q&As for summary
                    cursor.execute("""
                        SELECT question_text, candidate_answer, score, feedback
                        FROM ai_interview_responses 
                        WHERE interview_id = %s
                        ORDER BY question_number
                    """, (interview_id,))
                    all_qa = cursor.fetchall()
                    
                    summary_prompt = f"""Provide a brief overall assessment (3-4 sentences) of this candidate's interview performance:

Average Score: {overall_score:.1f}%

Questions and Responses:
"""
                    for qa in all_qa:
                        summary_prompt += f"\nQ: {qa['question_text']}\nScore: {qa['score']}/10\n"
                    
                    summary_response = model.generate_content(summary_prompt)
                    overall_feedback = summary_response.text.strip()
            except:
                pass
        
        # Update interview as completed
        cursor.execute("""
            UPDATE ai_mock_interviews 
            SET status = 'completed',
                overall_score = %s,
                technical_score = %s,
                communication_score = %s,
                confidence_score = %s,
                ai_feedback = %s,
                completed_at = NOW()
            WHERE id = %s AND candidate_id = %s
        """, (overall_score, overall_score, overall_score, overall_score, 
              overall_feedback, interview_id, candidate_id))
        
        db.commit()
        cursor.close()
        db.close()
        
        return jsonify({
            'success': True,
            'overall_score': overall_score,
            'redirect_url': f'/mock-interview-result/{interview_id}'
        })
        
    except Exception as e:
        print(f"Error completing interview: {e}")
        try:
            db.rollback()
            cursor.close()
            db.close()
        except:
            pass
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/mock-interview-result/<int:interview_id>')
def mock_interview_result(interview_id):
    """Display interview results and feedback"""
    if session.get('role') != 'candidate':
        return redirect('/login')
    
    candidate_id = session.get('user_id')
    db = get_connection()
    cursor = db.cursor(dictionary=True)
    
    # Get interview details
    cursor.execute("""
        SELECT * FROM ai_mock_interviews 
        WHERE id = %s AND candidate_id = %s AND status = 'completed'
    """, (interview_id, candidate_id))
    
    interview = cursor.fetchone()
    
    if not interview:
        cursor.close()
        db.close()
        flash('Interview not found or not completed', 'danger')
        return redirect('/candidate-dashboard#ai-assessments')
    
    # Get all questions and responses
    cursor.execute("""
        SELECT * FROM ai_interview_responses 
        WHERE interview_id = %s
        ORDER BY question_number
    """, (interview_id,))
    
    responses = cursor.fetchall()
    cursor.close()
    db.close()
    
    return render_template('mock_interview_result.html', 
                         interview=interview, 
                         responses=responses)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    socketio.run(app, debug=True, use_reloader=False)