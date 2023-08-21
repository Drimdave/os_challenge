# OS Challenge API

This project is a Flask-based API that provides endpoints for recording JSON payloads, retrieving recorded requests, user registration, and user login. It also features role-based access to certain endpoints and JWT for authentication.

## Requirements:

- Python 3.x
- Virtual environment (recommended)

## Setting Up:

1. **Clone the Repository:**
    ```bash
    git clone <https://github.com/Drimdave/os_challenge>
    cd <os_challenge>
    ```

2. **Set Up a Virtual Environment (Optional but Recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use: venv\Scripts\activate
    ```

3. **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4. **Set Up the Database:**
    ```bash
    python
    >>> from app import db
    >>> db.create_all()
    >>> exit()
    ```

5. **Run the Application:**
    ```bash
    python app.py
    ```

The application should now be running on `http://127.0.0.1:5000/`.

## Using the Application:

1. **Home Endpoint:** Accessible at the root URL, it provides an overview of available endpoints.
2. **/record:** Accepts a POST request to record a JSON payload.
3. **/requests:** Retrieves all recorded requests.
4. **/register:** Register a new user.
5. **/login:** Login and retrieve an authentication token.

## Notes:

- The application uses SQLite for data storage, so there's no need for external database setup.
- Ensure the `JWT_SECRET_KEY` in `app.py` is kept secret in a production environment.
- For deployment, you may need to make adjustments depending on the platform. For example, Heroku requires a `Procfile`.
