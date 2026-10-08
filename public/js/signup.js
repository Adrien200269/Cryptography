document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('signupForm');
  const alertBox = document.getElementById('alertBox');
  const submitBtn = document.getElementById('submitBtn');

  function showAlert(message, type = 'error') {
    alertBox.textContent = message;
    alertBox.className = `alert ${type}`;
    alertBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function clearAlert() {
    alertBox.textContent = '';
    alertBox.className = 'alert';
  }

  function validateClientPassword(pw) {
    if (pw.length < 10) return 'Password must be at least 10 characters long.';
    if (!/[A-Z]/.test(pw)) return 'Password must include at least one uppercase letter.';
    if (!/[a-z]/.test(pw)) return 'Password must include at least one lowercase letter.';
    if (!/[0-9]/.test(pw)) return 'Password must include at least one number.';
    if (!/[^A-Za-z0-9]/.test(pw)) return 'Password must include at least one special symbol.';
    return null;
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearAlert();

    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (!email) {
      showAlert('Please enter an email address.');
      return;
    }

    const pwError = validateClientPassword(password);
    if (pwError) {
      showAlert(pwError);
      return;
    }

    if (password !== confirmPassword) {
      showAlert('Passwords do not match.');
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = 'Encrypting & Registering...';

    try {
      // Relative URL fetch() to ensure same-origin HTTPS enforcement
      const response = await fetch('/api/signup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (!response.ok) {
        showAlert(data.error || 'Registration failed. Please try again.');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Register Account';
        return;
      }

      showAlert(data.message || 'Account successfully created! Redirecting to login...', 'success');
      setTimeout(() => {
        window.location.href = '/login.html';
      }, 1500);

    } catch (err) {
      showAlert('Network error: Could not connect to the secure server.');
      submitBtn.disabled = false;
      submitBtn.textContent = 'Register Account';
    }
  });
});
