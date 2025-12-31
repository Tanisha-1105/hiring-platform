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
socketio = SocketIO(app, cors_allowed_origins="*")


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
                msg.body = f"""
                    Hi,

                    Click the link below to reset your password:

                    {reset_link}

                    This link expires in 10 minutes.

                    If you didn't request this, ignore this email.
                """
                mail.send(msg)
            return "If the email exists, a reset link has been sent."
    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password_token(token):
    try:
        email = serializer.loads(
            token,
            salt="password-reset",
            max_age=600  # 10 minutes
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

    # Count applied jobs (placeholder for now)
    applied_count = 0

    cursor.close()
    db.close()

    return render_template(
        'candidate_dashboard.html',
        profile_completed=profile_completed,
        profile_percent=profile_percent,
        profile=profile,
        available_mentors=available_mentors,
        applied_count=applied_count,
        mentorship_requests=mentorship_requests
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

    cursor.execute("SELECT mr.id, mr.request_message, u.name AS candidate_name FROM mentorship_requests mr JOIN candidates u ON mr.candidate_id = u.id WHERE mr.mentor_id = %s AND mr.status = 'Accepted'", (mentor_id,))
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
        ORDER BY name ASC
    """)
    all_users = cursor.fetchall()

    # attach verification_status for mentors when available
    for u in all_users:
        try:
            if u.get('role') == 'Mentor':
                cursor.execute("SELECT verification_status FROM mentor_profiles WHERE mentor_id=%s", (u.get('id'),))
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

        # 4. Top skills in demand - Parse from candidate profiles
        cursor.close()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT skills FROM candidate_profiles WHERE skills IS NOT NULL AND skills != ''")
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
            skills_labels = ['JavaScript', 'Python', 'React', 'Django', 'SQL', 'AWS']
            skills_demand = [220, 190, 160, 140, 130, 110]

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
                   cp.resume_file
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
                   cp.resume_file
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
        cursor.execute("""
            SELECT a.id FROM applications a
            JOIN jobs j ON a.job_id = j.id
            WHERE a.id = %s AND j.recruiter_id = %s
        """, (app_id, session.get('user_id')))
        
        if not cursor.fetchone():
            flash("Application not found", "danger")
            return redirect('/applications')
        
        # Update application status
        cursor.execute("""
            UPDATE applications SET status = %s WHERE id = %s
        """, (new_status, app_id))
        
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

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == "__main__":
    socketio.run(app, debug=True)