import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from .logger import init_logger


logger = init_logger('user.email')


def send_password_email(
        app_password, 
        app_email, 
        first_name, 
        user_email, 
        user_name, 
        generated_password
):
    try:
        message = MIMEMultipart("alternative")
        message["From"] = app_email
        message["To"] = user_email
        message["Subject"] = "Welcome to KalSense"

        html = f"""
        <html>
        <body>
        <p>Hi {first_name},<br>
        Welcome! Your new user was created with the following details: <br>
        Your user name is: <b>{user_name}</b><br>
        Your password is: <b>{generated_password}</b><br>
        Please change it upon your first login.<br>
        </p>
        <p>Best Regards,<br>
        <i>IT Services Team</i>
        </p>
        </body>
        </html>
        """

        part = MIMEText(html, "html")
        message.attach(part)

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(app_email, app_password)
        text = message.as_string()
        server.sendmail(app_email, user_email, text)
        server.quit()
        logger.info(f"Email sent to {user_email}")
    except smtplib.SMTPException as e:
        logger.error(f"Failed to send email to {user_email}, error: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to send email to {user_email}, error: {str(e)}")
