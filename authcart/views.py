from django.shortcuts import render, redirect, HttpResponse
from django.contrib.auth.models import User
from django.views.generic import View
from django.contrib import messages
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from .utils import TokenGenerator, generate_token
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError
from django.core.mail import EmailMessage
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth import authenticate, login, logout, get_user_model

# Create your views here.

def signup(request):
    if request.method == "POST":
        email = request.POST['email']
        password = request.POST['pass1']
        confirm_password = request.POST['pass2']

        if password != confirm_password:
            messages.warning(request, "Password is Not Matching")
            return render(request, 'signup.html')

        try:
            if User.objects.get(username=email):
                messages.info(request, "Email is Taken")
                return render(request, 'signup.html')
        except Exception as identifier:
            pass
        
        # Create the user with email as username
        user = User.objects.create_user(email, email, password)
        user.is_active = False
        user.save()

        email_subject = "Activate Your Account"
        message = render_to_string('activate.html', {
            'user': user,
            'domain': '127.0.0.1:8000',
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user)
        })

        # Uncomment the following lines to send the email
        # email_message = EmailMessage(email_subject, message, settings.EMAIL_HOST_USER, [email])
        # email_message.send()

        messages.success(request, f"Activate Your Account by clicking the link in your email: {message}")
        return redirect('/auth/login/')

    return render(request, "signup.html")


class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception as identifier:
            user = None

        if user is not None and generate_token.check_token(user, token):
            user.is_active = True
            user.save()
            messages.info(request, "Account Activated Successfully")
            return redirect('/auth/login')
        
        return render(request, 'activatefail.html')


def handlelogin(request):
    if request.method == "POST":
        # Get the email and password from the request
        email = request.POST['email']
        userpassword = request.POST['pass1']

        # Authenticate user based on the email (requires customizing the backend if email is used as username)
        try:
            from django.contrib.auth.models import User
            user_obj = User.objects.get(email=email)  # Get the user object using email
            username = user_obj.username  # Extract the username corresponding to the email
            myuser = authenticate(username=username, password=userpassword)  # Authenticate user

            if myuser is not None:
                login(request, myuser)
                messages.success(request, "Invalid Credentials")
                return redirect('/auth/login')
            else:
                messages.error(request, "login successfull")
                return redirect('/')
        except User.DoesNotExist:
            messages.error(request, "No user found with this email")
            return redirect('/auth/login')

    return render(request, "login.html")
    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('pass1')

        # Authenticate the user directly with username (email) and password
        myuser = authenticate(request, username=email, password=password)

        if myuser is not None:
            login(request, myuser)  # Log the user in
            messages.success(request, "Login successful!")  # Show success message
            return redirect('/')  # Redirect to the home page
        else:
            messages.error(request, "Invalid email or password.")  # Show error message
            return redirect('/auth/login/')  # Stay on the login page if authentication fails

    return render(request, 'login.html')  # Render the login page if not a POST request

    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('pass1')

        # Get the User model
        User = get_user_model()

        # Directly try to authenticate and login the user
        myuser = authenticate(request, username=email, password=password)

        if myuser is not None:
            messages.error(request, "Invalid email or password.")
            return redirect('/auth/login/')
        else:
            
            login(request, myuser)
            messages.success(request, "Login successful!")
            return redirect('/')


    return render(request, 'login.html')


def handlelogout(request):
    logout(request)
    messages.info(request, "Logout Success")
    return redirect('/auth/login')


class RequestResetEmailView(View):
    def get(self, request):
        return render(request, 'request-reset-email.html')

    def post(self, request):
        email = request.POST['email']
        user = User.objects.filter(email=email)

        if user.exists():
            email_subject = '[Reset Your Password]'
            message = render_to_string('reset-user-password.html', {
                'domain': '127.0.0.1:8000',
                'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token': PasswordResetTokenGenerator().make_token(user[0])
            })

            # Uncomment the following lines to send the email
            # email_message = EmailMessage(email_subject, message, settings.EMAIL_HOST_USER, [email])
            # email_message.send()

            messages.info(request, f"We have sent you an email with instructions on how to reset the password: {message}")
            return render(request, 'request-reset-email.html')


class SetNewPasswordView(View):
    def get(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token
        }

        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.warning(request, "Password Reset Link is Invalid")
                return render(request, 'request-reset-email.html')

        except DjangoUnicodeDecodeError as identifier:
            pass

        return render(request, 'set-new-password.html', context)

    def post(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token
        }

        password = request.POST['pass1']
        confirm_password = request.POST['pass2']

        if password != confirm_password:
            messages.warning(request, "Passwords do not match")
            return render(request, 'set-new-password.html', context)

        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()
            messages.success(request, "Password Reset Successful. Please login with the new password.")
            return redirect('/auth/login/')

        except DjangoUnicodeDecodeError as identifier:
            messages.error(request, "Something went wrong.")
            return render(request, 'set-new-password.html', context)

        return render(request, 'set-new-password.html', context)
