# SCENARIOS

## Injection 

Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. This allows attackers to manipulate the query and execute unintended commands, potentially accessing or modifying data in unauthorized ways.

Real-life Example: SQL Injection

Scenario:
Imagine you are developing an online bookstore application using Python and a MySQL database. Users can search for books by entering keywords into a search field. Your backend code constructs an SQL query using the user’s input to retrieve matching books from the database.



```python
import mysql.connector

def search_books(keyword):
    db = mysql.connector.connect(
        host="localhost",
        user="username",
        password="password",
        database="bookstore"
    )
    cursor = db.cursor()
    
    # Vulnerable SQL query
    query = f"SELECT * FROM books WHERE title LIKE '%{keyword}%'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    for row in results:
        print(row)

search_books("Harry Potter")
```


## Explanation of Vulnerability:

In the above code, the keyword parameter is directly embedded into the SQL query string without any validation or sanitization. This makes the application vulnerable to SQL injection attacks. An attacker can manipulate the input to execute arbitrary SQL commands.

Attack Example:
An attacker could input the following keyword: ' OR '1'='1
This would result in the following SQL query being executed:


``` 
SELECT * FROM books WHERE title LIKE '%' OR '1'='1%'
```

The condition **'1'='1'** is always true, so this query returns all rows in the books table, effectively bypassing the search functionality and exposing the entire database contents.

Mitigation: Use Parameterized Queries and Prepared Statements

Secure Code:

```
import mysql.connector

def search_books(keyword):
    db = mysql.connector.connect(
        host="localhost",
        user="username",
        password="password",
        database="bookstore"
    )
    cursor = db.cursor()
    
    # Secure SQL query using parameterized queries
    query = "SELECT * FROM books WHERE title LIKE %s"
    cursor.execute(query, ('%' + keyword + '%',))
    
    results = cursor.fetchall()
    for row in results:
        print(row)

search_books("Harry Potter")
```

**Explanation of Mitigation:**

In the secure code, the SQL query uses a parameterized query, represented by %s in the query string. The user input (keyword) is passed as a parameter to the execute method. This ensures that the input is properly escaped and treated as a string literal rather than executable code, preventing SQL injection.

# Broken Authentication:

Broken authentication flaws occur when an application’s authentication mechanisms are improperly implemented, allowing attackers to compromise passwords, keys, or session tokens. This can lead to unauthorized access and allow attackers to assume other users' identities.

**Real-life Example: Session Hijacking**

Explanation of Vulnerability
Scenario:
Imagine you are developing a web application where users log in with a username and password. Upon successful authentication, the application creates a session for the user and stores the session ID in a cookie.

**Vulnerable Code Example:**

```
from flask import Flask, request, session, redirect

app = Flask(__name__)
app.secret_key = 'super_secret_key'

# Simulated user database
users = {
    "user1": "password1",
    "user2": "password2"
}

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if username in users and users[username] == password:
        session['user'] = username
        return redirect('/dashboard')
    else:
        return "Invalid credentials", 401

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return f"Welcome, {session['user']}!"
    else:
        return redirect('/login')

if __name__ == "__main__":
    app.run()
```

### Explanation of Vulnerability:

Session ID Predictability: If the session ID is predictable or easily guessable, an attacker can hijack the session by obtaining or guessing the session ID.
Insecure Transmission: If the session ID is transmitted over an insecure connection (e.g., HTTP instead of HTTPS), it can be intercepted by an attacker.


**Attack Example:**
An attacker could intercept a session ID using a man-in-the-middle attack on an insecure network, and then use that session ID to impersonate the user.

**Mitigation Techniques**

**1. Implement Multi-Factor Authentication (MFA)**
Multi-Factor Authentication (MFA) adds an extra layer of security by requiring additional verification methods (e.g., a code sent to a user's phone) beyond just a username and password.

**2. Ensure Secure Password Storage**
Passwords should be stored securely using strong hashing algorithms and appropriate salting.

**3. Proper Session Management**
Use Secure Cookies: Ensure that cookies storing session IDs are marked as Secure and HttpOnly to prevent them from being accessed through client-side scripts.
Regenerate Session IDs: Regenerate the session ID after login and periodically during the session to prevent session fixation attacks.
Use HTTPS: Always use HTTPS to encrypt data transmitted between the client and server, protecting the session ID from interception.


### Secure Code Example:

```
from flask import Flask, request, session, redirect
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = 'super_secret_key'

# Simulated user database with hashed passwords
users = {
    "user1": generate_password_hash("password1"),
    "user2": generate_password_hash("password2")
}

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if username in users and check_password_hash(users[username], password):
        session['user'] = username
        # Regenerate session ID after login
        session.permanent = True
        session.modified = True
        return redirect('/dashboard')
    else:
        return "Invalid credentials", 401

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return f"Welcome, {session['user']}!"
    else:
        return redirect('/login')

if __name__ == "__main__":
    app.run(ssl_context='adhoc')
```

Explanation of Mitigation:

**Password Hashing:** The generate_password_hash and check_password_hash functions from werkzeug.security ensure that passwords are stored securely.

**Session Security:** Regenerating the session ID after login helps prevent session fixation attacks. Running the application with HTTPS (ssl_context='adhoc') ensures secure transmission of session cookies.

**Secure Cookies:** Flask’s session management uses cookies that are marked as Secure and HttpOnly by default if the app is running over HTTPS.


# XML External Entities (XXE):

An XML External Entity (XXE) vulnerability occurs when an XML parser evaluates external entities within XML documents. This can lead to various security issues such as data exposure, denial of service, and server-side request forgery.

Real-life Example: Exposing Internal Files through an XML Endpoint

**Explanation of Vulnerability
Scenario:**
Imagine you are developing a web application that allows users to upload XML files. The application processes these XML files to extract and display the data. An XXE vulnerability can occur if the XML parser is not properly configured to disable external entity processing.

**Vulnerable Code Example:**

```
import xml.etree.ElementTree as ET

def process_xml(xml_data):
    root = ET.fromstring(xml_data)
    # Process the XML data
    for element in root.findall('.//data'):
        print(element.text)

# Example of XML data with an external entity
xml_data = '''
<!DOCTYPE data [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>
    &xxe;
</data>
'''

process_xml(xml_data)
```

**Explanation of Vulnerability:**

External Entities: The XML document defines an external entity xxe that references the contents of the /etc/passwd file.
Entity Expansion: When the XML parser processes the document, it tries to expand the &xxe; entity, potentially exposing sensitive data.
Attack Example:
An attacker could craft an XML file with an external entity pointing to sensitive files on the server:


```
<!DOCTYPE data [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>
    &xxe;
</data>
```

When this XML is processed by the vulnerable code, the contents of /etc/passwd would be exposed, leading to a potential data breach.

Mitigation Techniques
1. Disable External Entity Processing
Configure the XML parser to disallow the processing of external entities. This prevents the parser from accessing external resources defined in the XML document.

2. Use Secure XML Parsers
Use XML parsers that have secure default configurations, or explicitly configure them to be secure.

Secure Code Example:
Here’s how you can securely configure the xml.etree.ElementTree parser in Python to prevent XXE vulnerabilities:

```
import defusedxml.ElementTree as ET

def process_xml_secure(xml_data):
    # Secure XML processing using defusedxml
    parser = ET.XMLParser()
    root = ET.fromstring(xml_data, parser=parser)
    # Process the XML data
    for element in root.findall('.//data'):
        print(element.text)

# Example of XML data with an external entity (this will not be processed)
xml_data = '''
<!DOCTYPE data [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>
    &xxe;
</data>
'''

process_xml_secure(xml_data)
```

Explanation of Mitigation:

**Defusedxml Library:** The defusedxml library is used to securely parse XML data. It is specifically designed to prevent XXE and other XML-related vulnerabilities.
No External Entity Processing: The secure parser does not process external entities, effectively mitigating the XXE vulnerability.


# Broken Access Control

Broken access control occurs when restrictions on what authenticated users are allowed to do are not properly enforced. This can allow attackers to access unauthorized data or perform actions that they should not be able to.

Real-life Example: Accessing Other Users' Data by Manipulating URLs

Explanation of Vulnerability
Scenario:
Imagine you are developing a web application where users can view and edit their profiles. Each user profile is accessed via a URL like http://example.com/user/{userID}. If access control is not properly enforced, an attacker could manipulate the URL to access other users' profiles.

**Vulnerable Code Example:**
```
from flask import Flask, request, redirect, session

app = Flask(__name__)
app.secret_key = 'super_secret_key'

# Simulated user database
users = {
    1: {"username": "user1", "password": "password1"},
    2: {"username": "user2", "password": "password2"}
}

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    for user_id, user_info in users.items():
        if user_info['username'] == username and user_info['password'] == password:
            session['user_id'] = user_id
            return redirect(f'/user/{user_id}')
    return "Invalid credentials", 401

@app.route('/user/<int:user_id>')
def user_profile(user_id):
    # Vulnerable: No check to ensure the user is accessing their own profile
    user_info = users.get(user_id)
    if user_info:
        return f"User ID: {user_id}, Username: {user_info['username']}"
    return "User not found", 404

if __name__ == "__main__":
    app.run()
```

**Explanation of Vulnerability:**

No Access Control Check: The /user/<int:user_id> route does not verify whether the authenticated user is allowed to access the specified user_id.
URL Manipulation: An authenticated user can change the user_id in the URL to access other users' profiles.
Attack Example:
An attacker logs in as user1 and gets redirected to http://example.com/user/1. The attacker then changes the URL to http://example.com/user/2 to access user2's profile.

Mitigation Techniques
1. Implement Proper Access Controls
Ensure that only authorized users can access or perform actions on the resources they are permitted to.

2. Conduct Thorough Testing
Perform regular security testing, including penetration testing and code reviews, to identify and fix access control vulnerabilities.

**Secure Code Example:**
Here’s how you can implement proper access control in the Flask application:

```
from flask import Flask, request, redirect, session

app = Flask(__name__)
app.secret_key = 'super_secret_key'

# Simulated user database
users = {
    1: {"username": "user1", "password": "password1"},
    2: {"username": "user2", "password": "password2"}
}

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    for user_id, user_info in users.items():
        if user_info['username'] == username and user_info['password'] == password:
            session['user_id'] = user_id
            return redirect(f'/user/{user_id}')
    return "Invalid credentials", 401

@app.route('/user/<int:user_id>')
def user_profile(user_id):
    # Secure: Check if the logged-in user is accessing their own profile
    if 'user_id' not in session:
        return redirect('/login')
    
    if session['user_id'] != user_id:
        return "Access denied", 403

    user_info = users.get(user_id)
    if user_info:
        return f"User ID: {user_id}, Username: {user_info['username']}"
    return "User not found", 404

if __name__ == "__main__":
    app.run()
```


Explanation of Mitigation:

Session Check: Ensure the user is logged in by checking the session.
User ID Validation: Verify that the user_id in the URL matches the authenticated user's ID stored in the session.
Access Denied Response: Return a 403 Forbidden response if the user tries to access another user's profile.




