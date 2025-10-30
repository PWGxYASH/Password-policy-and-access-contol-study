document.addEventListener('DOMContentLoaded', function () {
    const form = document.querySelector('form');
    if (!form) return;

    const submitBtn = form.querySelector('button[type="submit"]');

    function showAlert(type, message) {
        // remove existing alerts
        const existing = form.parentElement.querySelector('.fp-alert');
        if (existing) existing.remove();

        const div = document.createElement('div');
        div.className = `alert alert-${type} fp-alert`;
        div.role = 'alert';
        div.textContent = message;
        form.parentElement.insertBefore(div, form);
        // auto-dismiss after 6s
        setTimeout(() => div.remove(), 6000);
    }

    function validEmail(email) {
        return /^\S+@\S+\.\S+$/.test(email);
    }

    form.addEventListener('submit', async function (e) {
        e.preventDefault();
        const email = (form.elements['email'] || {}).value || '';
        if (!validEmail(email.trim())) {
            showAlert('danger', 'Please enter a valid email address.');
            return;
        }

        if (submitBtn) {
            submitBtn.disabled = true;
            var originalHtml = submitBtn.innerHTML;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Sending...';
        }

        try {
            const res = await fetch(window.location.pathname, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ email: email.trim() })
            });

            let payload;
            try { payload = await res.json(); } catch (err) { payload = null; }

            if (res.ok) {
                showAlert('success', (payload && payload.message) || 'If the email exists, an OTP has been sent.');
                form.reset();
            } else {
                showAlert('danger', (payload && (payload.error || payload.message)) || 'Failed to send OTP.');
            }
        } catch (err) {
            showAlert('danger', 'Network error. Please try again.');
        } finally {
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalHtml;
            }
        }
    });
});