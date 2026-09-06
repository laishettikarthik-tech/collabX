from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session
)

import sqlite3
import os

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename


# ==========================================
# FLASK APP
# ==========================================

app = Flask(__name__)

app.secret_key = "collabx-secret-key-change-this"


# ==========================================
# PROFILE IMAGE SETTINGS
# ==========================================

UPLOAD_FOLDER = "static/uploads"

ALLOWED_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp"
}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_db():

    connection = sqlite3.connect(
        "collabx.db"
    )

    connection.row_factory = sqlite3.Row

    return connection


# ==========================================
# CHECK IMAGE EXTENSION
# ==========================================

def allowed_file(filename):

    return (
        "." in filename
        and
        filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


# ==========================================
# CREATE DATABASE
# ==========================================

def create_database():

    connection = get_db()


    # ======================================
    # USERS TABLE
    # ======================================

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            first_name TEXT NOT NULL,

            last_name TEXT NOT NULL,

            email TEXT UNIQUE NOT NULL,

            role TEXT NOT NULL,

            password TEXT NOT NULL,

            created_at TIMESTAMP
            DEFAULT CURRENT_TIMESTAMP

        )
    """)


    # ======================================
    # PROFILES TABLE
    # ======================================

    connection.execute("""
        CREATE TABLE IF NOT EXISTS profiles (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER UNIQUE NOT NULL,

            profile_picture TEXT,

            bio TEXT,

            skills TEXT,

            looking_for TEXT,

            location TEXT,

            availability TEXT,

            github TEXT,

            linkedin TEXT,

            youtube TEXT,

            portfolio TEXT,

            FOREIGN KEY (user_id)
            REFERENCES users(id)

        )
    """)


    # ======================================
    # INVITATIONS TABLE
    # ======================================

    connection.execute("""
        CREATE TABLE IF NOT EXISTS invitations (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            sender_id INTEGER NOT NULL,

            receiver_id INTEGER NOT NULL,

            message TEXT,

            status TEXT DEFAULT 'pending',

            created_at TIMESTAMP
            DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (sender_id)
            REFERENCES users(id),

            FOREIGN KEY (receiver_id)
            REFERENCES users(id)

        )
    """)


    # ======================================
    # MESSAGES TABLE
    # ======================================

    connection.execute("""
        CREATE TABLE IF NOT EXISTS messages (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            sender_id INTEGER NOT NULL,

            receiver_id INTEGER NOT NULL,

            message TEXT NOT NULL,

            created_at TIMESTAMP
            DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (sender_id)
            REFERENCES users(id),

            FOREIGN KEY (receiver_id)
            REFERENCES users(id)

        )
    """)


    connection.commit()

    connection.close()


# ==========================================
# HOME / SIGNUP PAGE
# ==========================================

@app.route("/")
def home():

    return render_template(
        "signup.html"
    )


# ==========================================
# SIGNUP
# ==========================================

@app.route(
    "/signup",
    methods=["POST"]
)
def signup():

    first_name = request.form.get(
        "first_name",
        ""
    ).strip()

    last_name = request.form.get(
        "last_name",
        ""
    ).strip()

    email = request.form.get(
        "email",
        ""
    ).lower().strip()

    role = request.form.get(
        "role",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )


    # ======================================
    # BASIC VALIDATION
    # ======================================

    if not first_name:

        return render_template(
            "signup.html",
            error="First name is required."
        )


    if not last_name:

        return render_template(
            "signup.html",
            error="Last name is required."
        )


    if not email:

        return render_template(
            "signup.html",
            error="Email is required."
        )


    if not role:

        return render_template(
            "signup.html",
            error="Please select your role."
        )


    if len(password) < 8:

        return render_template(
            "signup.html",
            error="Password must be at least 8 characters."
        )


    # ======================================
    # HASH PASSWORD
    # ======================================

    hashed_password = generate_password_hash(
        password
    )


    connection = get_db()


    try:

        cursor = connection.execute("""
            INSERT INTO users
            (
                first_name,
                last_name,
                email,
                role,
                password
            )

            VALUES (?, ?, ?, ?, ?)

        """, (
            first_name,
            last_name,
            email,
            role,
            hashed_password
        ))


        user_id = cursor.lastrowid


        # Create empty profile

        connection.execute("""
            INSERT INTO profiles
            (user_id)

            VALUES (?)

        """, (
            user_id,
        ))


        connection.commit()


    except sqlite3.IntegrityError:

        connection.close()

        return render_template(
            "signup.html",
            error="An account with this email already exists."
        )


    connection.close()


    return render_template(
        "login.html",
        message="Account created successfully! Please login."
    )


# ==========================================
# LOGIN
# ==========================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).lower().strip()

        password = request.form.get(
            "password",
            ""
        )


        connection = get_db()


        user = connection.execute("""
            SELECT *
            FROM users

            WHERE email = ?

        """, (
            email,
        )).fetchone()


        connection.close()


        if user is None:

            return render_template(
                "login.html",
                error="Email or password is incorrect."
            )


        if not check_password_hash(
            user["password"],
            password
        ):

            return render_template(
                "login.html",
                error="Email or password is incorrect."
            )


        # ==================================
        # CREATE SESSION
        # ==================================

        session["user_id"] = user["id"]

        session["user_name"] = (
            user["first_name"]
        )

        session["user_role"] = (
            user["role"]
        )

        session["user_email"] = (
            user["email"]
        )


        return redirect(
            url_for("dashboard")
        )


    return render_template(
        "login.html"
    )


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    current_user_id = session["user_id"]

    connection = get_db()

    # ==========================================
    # GET CURRENT USER
    # ==========================================

    user = connection.execute("""
        SELECT
            users.*,
            profiles.*
        FROM users
        LEFT JOIN profiles
        ON users.id = profiles.user_id
        WHERE users.id = ?
    """, (
        current_user_id,
    )).fetchone()

    # ==========================================
    # PROFILE COMPLETION
    # ==========================================

    profile_fields = [
        user["profile_picture"],
        user["bio"],
        user["skills"],
        user["looking_for"],
        user["location"],
        user["availability"],
        user["github"],
        user["linkedin"],
        user["youtube"],
        user["portfolio"]
    ]

    completed_fields = sum(
        1
        for field in profile_fields
        if field and str(field).strip()
    )

    profile_completion = int(
        (completed_fields / len(profile_fields)) * 100
    )

    # ==========================================
    # ACCEPTED COLLABORATIONS
    # ==========================================

    collaborations_count = connection.execute("""
        SELECT COUNT(*) AS count
        FROM invitations
        WHERE
            (sender_id = ? OR receiver_id = ?)
            AND status = 'accepted'
    """, (
        current_user_id,
        current_user_id
    )).fetchone()["count"]

    # ==========================================
    # PENDING INVITATIONS
    # ==========================================

    pending_invitations = connection.execute("""
        SELECT COUNT(*) AS count
        FROM invitations
        WHERE receiver_id = ?
        AND status = 'pending'
    """, (
        current_user_id,
    )).fetchone()["count"]

    # ==========================================
    # UNREAD MESSAGES
    # ==========================================

    unread_messages_count = connection.execute("""
        SELECT COUNT(*) AS count
        FROM messages
        WHERE receiver_id = ?
        AND is_read = 0
    """, (
        current_user_id,
    )).fetchone()["count"]

    connection.close()

    return render_template(
        "dashboard.html",
        user=user,
        collaborations_count=collaborations_count,
        pending_invitations=pending_invitations,
        unread_messages_count=unread_messages_count,
        profile_completion=profile_completion
    )


# ==========================================
# EDIT PROFILE
# ==========================================

@app.route("/edit-profile", methods=["GET", "POST"])
def edit_profile():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]

    connection = get_db()

    if request.method == "POST":

        bio = request.form.get("bio", "").strip()
        skills = request.form.get("skills", "").strip()
        looking_for = request.form.get("looking_for", "").strip()
        location = request.form.get("location", "").strip()
        availability = request.form.get("availability", "").strip()
        github = request.form.get("github", "").strip()
        linkedin = request.form.get("linkedin", "").strip()
        youtube = request.form.get("youtube", "").strip()
        portfolio = request.form.get("portfolio", "").strip()

        # Check if profile already exists
        existing_profile = connection.execute("""
            SELECT id
            FROM profiles
            WHERE user_id = ?
        """, (user_id,)).fetchone()

        # ------------------------------------------
        # PROFILE IMAGE
        # ------------------------------------------

        profile_picture = None

        if "profile_picture" in request.files:

            file = request.files["profile_picture"]

            if file and file.filename != "":

                if allowed_file(file.filename):

                    original_filename = secure_filename(
                        file.filename
                    )

                    filename = (
                        str(user_id)
                        + "_"
                        + original_filename
                    )

                    file.save(
                        os.path.join(
                            app.config["UPLOAD_FOLDER"],
                            filename
                        )
                    )

                    profile_picture = "uploads/" + filename

        # ------------------------------------------
        # UPDATE EXISTING PROFILE
        # ------------------------------------------

        if existing_profile:

            if profile_picture:

                connection.execute("""
                    UPDATE profiles
                    SET
                        bio = ?,
                        skills = ?,
                        looking_for = ?,
                        location = ?,
                        availability = ?,
                        github = ?,
                        linkedin = ?,
                        youtube = ?,
                        portfolio = ?,
                        profile_picture = ?
                    WHERE user_id = ?
                """, (
                    bio,
                    skills,
                    looking_for,
                    location,
                    availability,
                    github,
                    linkedin,
                    youtube,
                    portfolio,
                    profile_picture,
                    user_id
                ))

            else:

                connection.execute("""
                    UPDATE profiles
                    SET
                        bio = ?,
                        skills = ?,
                        looking_for = ?,
                        location = ?,
                        availability = ?,
                        github = ?,
                        linkedin = ?,
                        youtube = ?,
                        portfolio = ?
                    WHERE user_id = ?
                """, (
                    bio,
                    skills,
                    looking_for,
                    location,
                    availability,
                    github,
                    linkedin,
                    youtube,
                    portfolio,
                    user_id
                ))

        # ------------------------------------------
        # CREATE PROFILE IF IT DOES NOT EXIST
        # ------------------------------------------

        else:

            connection.execute("""
                INSERT INTO profiles (
                    user_id,
                    bio,
                    skills,
                    looking_for,
                    location,
                    availability,
                    github,
                    linkedin,
                    youtube,
                    portfolio,
                    profile_picture
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id,
                bio,
                skills,
                looking_for,
                location,
                availability,
                github,
                linkedin,
                youtube,
                portfolio,
                profile_picture
            ))

        connection.commit()
        connection.close()

        return redirect(url_for("profile"))

    # ------------------------------------------
    # LOAD PROFILE
    # ------------------------------------------

    user = connection.execute("""
        SELECT
            users.*,
            profiles.*
        FROM users
        LEFT JOIN profiles
        ON users.id = profiles.user_id
        WHERE users.id = ?
    """, (user_id,)).fetchone()

    connection.close()

    return render_template(
        "edit_profile.html",
        user=user
    )

# ==========================================
# PUBLIC PROFILE
# ==========================================

@app.route(
    "/profile/<int:user_id>"
)
def public_profile(user_id):

    connection = get_db()


    user = connection.execute("""
        SELECT
            users.*,
            profiles.*

        FROM users

        LEFT JOIN profiles
        ON users.id = profiles.user_id

        WHERE users.id = ?

    """, (
        user_id,
    )).fetchone()


    connection.close()


    if user is None:

        return "User not found", 404


    return render_template(
        "profile.html",
        user=user
    )


# ==========================================
# MY PROFILE
# ==========================================

@app.route("/profile")
def profile():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )


    return redirect(
        url_for(
            "public_profile",
            user_id=session["user_id"]
        )
    )


# ==========================================
# DISCOVER USERS
# ==========================================

@app.route("/discover")
def discover():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )


    search = request.args.get(
        "search",
        ""
    ).strip()

    role = request.args.get(
        "role",
        ""
    ).strip()

    skills = request.args.get(
        "skills",
        ""
    ).strip()

    location = request.args.get(
        "location",
        ""
    ).strip()

    availability = request.args.get(
        "availability",
        ""
    ).strip()


    # ======================================
    # BASE QUERY
    # ======================================

    query = """
        SELECT
            users.id,
            users.first_name,
            users.last_name,
            users.email,
            users.role,

            profiles.profile_picture,
            profiles.bio,
            profiles.skills,
            profiles.looking_for,
            profiles.location,
            profiles.availability

        FROM users

        LEFT JOIN profiles
        ON users.id = profiles.user_id

        WHERE users.id != ?
    """


    parameters = [
        session["user_id"]
    ]


    # ======================================
    # SEARCH
    # ======================================

    if search:

        query += """
            AND (
                users.first_name LIKE ?
                OR users.last_name LIKE ?
                OR users.role LIKE ?
                OR profiles.bio LIKE ?
                OR profiles.skills LIKE ?
                OR profiles.looking_for LIKE ?
                OR profiles.location LIKE ?
            )
        """


        search_value = f"%{search}%"


        parameters.extend([
            search_value,
            search_value,
            search_value,
            search_value,
            search_value,
            search_value,
            search_value
        ])


    # ======================================
    # ROLE FILTER
    # ======================================

    if role:

        query += """
            AND users.role = ?
        """


        parameters.append(
            role
        )


    # ======================================
    # SKILLS FILTER
    # ======================================

    if skills:

        query += """
            AND profiles.skills LIKE ?
        """


        parameters.append(
            f"%{skills}%"
        )


    # ======================================
    # LOCATION FILTER
    # ======================================

    if location:

        query += """
            AND profiles.location LIKE ?
        """


        parameters.append(
            f"%{location}%"
        )


    # ======================================
    # AVAILABILITY FILTER
    # ======================================

    if availability:

        query += """
            AND profiles.availability = ?
        """


        parameters.append(
            availability
        )


    query += """
        ORDER BY users.first_name ASC
    """


    connection = get_db()


    users = connection.execute(
        query,
        parameters
    ).fetchall()


    connection.close()


    return render_template(
        "discover.html",

        users=users,

        search=search,

        role=role,

        skills=skills,

        location=location,

        availability=availability
    )


# ==========================================
# INVITE COLLABORATOR
# ==========================================

@app.route(
    "/invite/<int:user_id>",
    methods=["POST"]
)
def invite(user_id):

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )


    sender_id = session["user_id"]


    if sender_id == user_id:

        return redirect(
            url_for("discover")
        )


    connection = get_db()


    # ======================================
    # CHECK USER
    # ======================================

    receiver = connection.execute("""
        SELECT id
        FROM users

        WHERE id = ?

    """, (
        user_id,
    )).fetchone()


    if receiver is None:

        connection.close()

        return "User not found", 404


    # ======================================
    # CHECK PENDING INVITATION
    # ======================================

    existing = connection.execute("""
        SELECT id
        FROM invitations

        WHERE sender_id = ?

        AND receiver_id = ?

        AND status = 'pending'

    """, (
        sender_id,
        user_id
    )).fetchone()


    if existing:

        connection.close()

        return redirect(
            url_for("discover")
        )


    # ======================================
    # INVITATION MESSAGE
    # ======================================

    message = request.form.get(
        "message",
        ""
    ).strip()


    connection.execute("""
        INSERT INTO invitations
        (
            sender_id,
            receiver_id,
            message,
            status
        )

        VALUES (?, ?, ?, 'pending')

    """, (
        sender_id,
        user_id,
        message
    ))


    connection.commit()

    connection.close()


    return redirect(
        url_for("discover")
    )


# ==========================================
# INVITATIONS
# ==========================================

@app.route("/invitations")
def invitations():

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    connection = get_db()

    # ======================================
    # INCOMING INVITATIONS
    # ======================================

    incoming = connection.execute("""
        SELECT
            invitations.id,
            invitations.message,
            invitations.status,
            invitations.created_at,

            users.id AS sender_id,
            users.first_name AS sender_first_name,
            users.last_name AS sender_last_name,
            users.role AS sender_role,

            profiles.profile_picture AS sender_picture,
            profiles.bio AS sender_bio

        FROM invitations

        JOIN users
        ON invitations.sender_id = users.id

        LEFT JOIN profiles
        ON users.id = profiles.user_id

        WHERE invitations.receiver_id = ?

        ORDER BY invitations.created_at DESC

    """, (
        user_id,
    )).fetchall()


    # ======================================
    # OUTGOING INVITATIONS
    # ======================================

    outgoing = connection.execute("""
        SELECT
            invitations.id,
            invitations.message,
            invitations.status,
            invitations.created_at,

            users.id AS receiver_id,
            users.first_name AS receiver_first_name,
            users.last_name AS receiver_last_name,
            users.role AS receiver_role,

            profiles.profile_picture AS receiver_picture

        FROM invitations

        JOIN users
        ON invitations.receiver_id = users.id

        LEFT JOIN profiles
        ON users.id = profiles.user_id

        WHERE invitations.sender_id = ?

        ORDER BY invitations.created_at DESC

    """, (
        user_id,
    )).fetchall()


    connection.close()


    return render_template(
        "invitations.html",
        incoming=incoming,
        outgoing=outgoing
    )

# ==========================================
# ACCEPT INVITATION
# ==========================================

@app.route(
    "/invitation/<int:invitation_id>/accept",
    methods=["POST"]
)
def accept_invitation(invitation_id):

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )


    user_id = session["user_id"]

    connection = get_db()


    invitation = connection.execute("""
        SELECT *
        FROM invitations

        WHERE id = ?

        AND receiver_id = ?

        AND status = 'pending'

    """, (
        invitation_id,
        user_id
    )).fetchone()


    if invitation is None:

        connection.close()

        return "Invitation not found", 404


    connection.execute("""
        UPDATE invitations

        SET status = 'accepted'

        WHERE id = ?

    """, (
        invitation_id,
    ))


    connection.commit()

    connection.close()


    return redirect(
        url_for("invitations")
    )


# ==========================================
# REJECT INVITATION
# ==========================================

@app.route(
    "/invitation/<int:invitation_id>/reject",
    methods=["POST"]
)
def reject_invitation(invitation_id):

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )


    user_id = session["user_id"]

    connection = get_db()


    invitation = connection.execute("""
        SELECT *
        FROM invitations

        WHERE id = ?

        AND receiver_id = ?

        AND status = 'pending'

    """, (
        invitation_id,
        user_id
    )).fetchone()


    if invitation is None:

        connection.close()

        return "Invitation not found", 404


    connection.execute("""
        UPDATE invitations

        SET status = 'rejected'

        WHERE id = ?

    """, (
        invitation_id,
    ))


    connection.commit()

    connection.close()


    return redirect(
        url_for("invitations")
    )


# ==========================================
# MY COLLABORATIONS
# ==========================================

@app.route("/collaborations")
def collaborations():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )


    user_id = session["user_id"]

    connection = get_db()


    collaborations = connection.execute("""
        SELECT
            invitations.id,
            invitations.created_at,

            CASE
                WHEN invitations.sender_id = ?
                THEN receiver.id
                ELSE sender.id
            END AS collaborator_id,

            CASE
                WHEN invitations.sender_id = ?
                THEN receiver.first_name
                ELSE sender.first_name
            END AS collaborator_first_name,

            CASE
                WHEN invitations.sender_id = ?
                THEN receiver.last_name
                ELSE sender.last_name
            END AS collaborator_last_name,

            CASE
                WHEN invitations.sender_id = ?
                THEN receiver.role
                ELSE sender.role
            END AS collaborator_role,

            CASE
                WHEN invitations.sender_id = ?
                THEN receiver.email
                ELSE sender.email
            END AS collaborator_email,

            CASE
                WHEN invitations.sender_id = ?
                THEN receiver_profile.profile_picture
                ELSE sender_profile.profile_picture
            END AS collaborator_picture,

            CASE
                WHEN invitations.sender_id = ?
                THEN receiver_profile.bio
                ELSE sender_profile.bio
            END AS collaborator_bio,

            CASE
                WHEN invitations.sender_id = ?
                THEN receiver_profile.location
                ELSE sender_profile.location
            END AS collaborator_location

        FROM invitations

        JOIN users AS sender
        ON invitations.sender_id = sender.id

        JOIN users AS receiver
        ON invitations.receiver_id = receiver.id

        LEFT JOIN profiles AS sender_profile
        ON sender.id = sender_profile.user_id

        LEFT JOIN profiles AS receiver_profile
        ON receiver.id = receiver_profile.user_id

        WHERE
            (
                invitations.sender_id = ?
                OR invitations.receiver_id = ?
            )

        AND invitations.status = 'accepted'

        ORDER BY invitations.created_at DESC

    """, (
        user_id,
        user_id,
        user_id,
        user_id,
        user_id,
        user_id,
        user_id,
        user_id,
        user_id,
        user_id
    )).fetchall()


    connection.close()


    return render_template(
        "collaborations.html",
        collaborations=collaborations
    )


# ==========================================
# CHAT
# ==========================================

@app.route(
    "/chat/<int:user_id>",
    methods=["GET", "POST"]
)
def chat(user_id):

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )


    current_user_id = session["user_id"]


    # ======================================
    # PREVENT SELF CHAT
    # ======================================

    if current_user_id == user_id:

        return redirect(
            url_for("collaborations")
        )


    connection = get_db()


    # ======================================
    # GET OTHER USER
    # ======================================

    other_user = connection.execute("""
        SELECT
            users.id,
            users.first_name,
            users.last_name,
            users.role,
            profiles.profile_picture

        FROM users

        LEFT JOIN profiles
        ON users.id = profiles.user_id

        WHERE users.id = ?

    """, (
        user_id,
    )).fetchone()


    if other_user is None:

        connection.close()

        return "User not found", 404


    # ======================================
    # CHECK ACCEPTED COLLABORATION
    # ======================================

    collaboration = connection.execute("""
        SELECT id

        FROM invitations

        WHERE status = 'accepted'

        AND (
            (
                sender_id = ?
                AND receiver_id = ?
            )

            OR

            (
                sender_id = ?
                AND receiver_id = ?
            )
        )

    """, (
        current_user_id,
        user_id,
        user_id,
        current_user_id
    )).fetchone()


    if collaboration is None:

        connection.close()

        return (
            "You can only message accepted collaborators.",
            403
        )


    # ======================================
    # SEND MESSAGE
    # ======================================

    if request.method == "POST":

        message = request.form.get(
            "message",
            ""
        ).strip()


        if message:

            connection.execute("""
                INSERT INTO messages
                (
                    sender_id,
                    receiver_id,
                    message
                )

                VALUES (?, ?, ?)

            """, (
                current_user_id,
                user_id,
                message
            ))


            connection.commit()


    # ======================================
    # GET MESSAGES
    # ======================================

    messages = connection.execute("""
        SELECT
            messages.id,
            messages.sender_id,
            messages.receiver_id,
            messages.message,
            messages.created_at,

            users.first_name,
            users.last_name

        FROM messages

        JOIN users
        ON messages.sender_id = users.id

        WHERE
            (
                messages.sender_id = ?
                AND messages.receiver_id = ?
            )

            OR

            (
                messages.sender_id = ?
                AND messages.receiver_id = ?
            )

        ORDER BY messages.created_at ASC

    """, (
        current_user_id,
        user_id,
        user_id,
        current_user_id
    )).fetchall()


    connection.close()


    return render_template(
        "chat.html",

        other_user=other_user,

        messages=messages
    )


# ==========================================
# MESSAGES INBOX
# ==========================================

@app.context_processor
def inject_unread_messages():

    if "user_id" not in session:
        return {
            "unread_messages": 0,
            "unread_invitations": 0
        }

    connection = get_db()

    unread_messages = connection.execute("""
        SELECT COUNT(*) AS count
        FROM messages
        WHERE receiver_id = ?
        AND is_read = 0
    """, (session["user_id"],)).fetchone()["count"]

    unread_invitations = connection.execute("""
        SELECT COUNT(*) AS count
        FROM invitations
        WHERE receiver_id = ?
        AND status = 'pending'
    """, (session["user_id"],)).fetchone()["count"]

    connection.close()

    return {
        "unread_messages": unread_messages,
        "unread_invitations": unread_invitations
    }

@app.route("/messages")
def messages_inbox():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )


    current_user_id = session["user_id"]

    connection = get_db()


    conversations = connection.execute("""
        SELECT DISTINCT

            CASE
                WHEN sender_id = ?
                THEN receiver_id
                ELSE sender_id
            END AS other_user_id

        FROM messages

        WHERE sender_id = ?
        OR receiver_id = ?

    """, (
        current_user_id,
        current_user_id,
        current_user_id
    )).fetchall()


    users = []


    for conversation in conversations:

        other_user_id = conversation["other_user_id"]


        user = connection.execute("""
            SELECT
                users.id,
                users.first_name,
                users.last_name,
                users.role,
                profiles.profile_picture

            FROM users

            LEFT JOIN profiles
            ON users.id = profiles.user_id

            WHERE users.id = ?

        """, (
            other_user_id,
        )).fetchone()


        last_message = connection.execute("""
            SELECT
                message,
                created_at,
                sender_id

            FROM messages

            WHERE
                (
                    sender_id = ?
                    AND receiver_id = ?
                )

                OR

                (
                    sender_id = ?
                    AND receiver_id = ?
                )

            ORDER BY created_at DESC

            LIMIT 1

        """, (
            current_user_id,
            other_user_id,
            other_user_id,
            current_user_id
        )).fetchone()


        unread = connection.execute("""
            SELECT COUNT(*) AS count

            FROM messages

            WHERE sender_id = ?
            AND receiver_id = ?
            AND is_read = 0

        """, (
            other_user_id,
            current_user_id
        )).fetchone()["count"]


        users.append({
            "user": user,
            "last_message": last_message,
            "unread": unread
        })


    connection.close()


    return render_template(
        "messages.html",
        conversations=users
    )


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout")
def logout():

    session.clear()


    return redirect(
        url_for("login")
    )


# ==========================================
# START SERVER
# ==========================================

if __name__ == "__main__":

    create_database()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )

# ==========================================
# CHAT
# ==========================================

@app.route("/chat/<int:user_id>", methods=["GET", "POST"])
def chat(user_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    current_user_id = session["user_id"]

    connection = get_db()

    # Get the person we are chatting with
    user = connection.execute("""
        SELECT
            users.*,
            profiles.*
        FROM users
        LEFT JOIN profiles
        ON users.id = profiles.user_id
        WHERE users.id = ?
    """, (user_id,)).fetchone()

    if user is None:
        connection.close()
        return "User not found", 404

    # ==========================================
    # MARK INCOMING MESSAGES AS READ
    # ==========================================

    connection.execute("""
        UPDATE messages
        SET is_read = 1
        WHERE sender_id = ?
          AND receiver_id = ?
          AND is_read = 0
    """, (
        user_id,
        current_user_id
    ))

    connection.commit()

    # ==========================================
    # SEND MESSAGE
    # ==========================================

    if request.method == "POST":

        message = request.form.get(
            "message",
            ""
        ).strip()

        if message:

            connection.execute("""
                INSERT INTO messages
                (
                    sender_id,
                    receiver_id,
                    message
                )
                VALUES (?, ?, ?)
            """, (
                current_user_id,
                user_id,
                message
            ))

            connection.commit()

    # ==========================================
    # GET CONVERSATION
    # ==========================================

    messages = connection.execute("""
        SELECT *
        FROM messages
        WHERE
            (sender_id = ? AND receiver_id = ?)
            OR
            (sender_id = ? AND receiver_id = ?)
        ORDER BY created_at ASC
    """, (
        current_user_id,
        user_id,
        user_id,
        current_user_id
    )).fetchall()

    connection.close()

    return render_template(
        "chat.html",
        user=user,
        messages=messages
    )