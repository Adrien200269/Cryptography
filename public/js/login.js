document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('loginForm');
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

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearAlert();

    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;

    if (!email || !password) {
      showAlert('Please enter both email and password.');
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = 'Authenticating...';

    try {
      // Relative URL fetch() to maintain secure session origin
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (!response.ok) {
        showAlert(data.error || 'Authentication failed.');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Sign In';
        return;
      }

      showAlert('Authenticated successfully. Redirecting...', 'success');
      window.location.href = data.redirectTo || '/welcome.html';

    } catch (err) {
      showAlert('Network error: Could not reach the secure server.');
      submitBtn.disabled = false;
      submitBtn.textContent = 'Sign In';
    }
  });
});
