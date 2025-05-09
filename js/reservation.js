document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('reservation-form');
    const formErrors = document.getElementById('form-errors');
    const formSuccess = document.getElementById('form-success');

    // Google Sheets Script Web App URL (you'll need to replace this with your actual deployed Google Apps Script web app URL)
    const GOOGLE_SHEETS_ENDPOINT = 'YOUR_GOOGLE_SHEETS_WEB_APP_URL';

    // Form validation function
    function validateForm(formData) {
        const errors = [];

        // Name validation
        if (!formData.name || formData.name.trim().length < 2) {
            errors.push('Please enter a valid name.');
        }

        // Email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!formData.email || !emailRegex.test(formData.email)) {
            errors.push('Please enter a valid email address.');
        }

        // Phone validation (basic check for Indonesian phone numbers)
        const phoneRegex = /^(\+62|62|0)8[1-9][0-9]{6,10}$/;
        if (!formData.phone || !phoneRegex.test(formData.phone)) {
            errors.push('Please enter a valid Indonesian phone number.');
        }

        // Date validation
        const selectedDate = new Date(formData.date);
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        if (!formData.date || selectedDate < today) {
            errors.push('Please select a valid future date.');
        }

        // Time validation
        if (!formData.time) {
            errors.push('Please select a reservation time.');
        }

        // Guest validation
        const guests = parseInt(formData.guests);
        if (!formData.guests || isNaN(guests) || guests < 1 || guests > 10) {
            errors.push('Please select a valid number of guests (1-10).');
        }

        return errors;
    }

    // Form submission handler
    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        // Reset previous messages
        formErrors.style.display = 'none';
        formSuccess.style.display = 'none';
        formErrors.innerHTML = '';

        // Collect form data
        const formData = {
            name: document.getElementById('name').value.trim(),
            email: document.getElementById('email').value.trim(),
            phone: document.getElementById('phone').value.trim(),
            date: document.getElementById('date').value,
            time: document.getElementById('time').value,
            guests: document.getElementById('guests').value,
            specialRequests: document.getElementById('special-requests').value.trim() || 'None'
        };

        // Validate form
        const validationErrors = validateForm(formData);
        
        if (validationErrors.length > 0) {
            formErrors.innerHTML = validationErrors.map(error => `<p>• ${error}</p>`).join('');
            formErrors.style.display = 'block';
            return;
        }

        try {
            // Submit to Google Sheets
            const response = await fetch(GOOGLE_SHEETS_ENDPOINT, {
                method: 'POST',
                mode: 'cors',
                cache: 'no-cache',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(formData)
            });

            if (!response.ok) {
                throw new Error('Reservation submission failed');
            }

            // Show success message
            form.reset();
            formSuccess.style.display = 'block';
        } catch (error) {
            // Show error message
            formErrors.innerHTML = `<p>• Unable to submit reservation. Please try again later.</p>`;
            formErrors.style.display = 'block';
            console.error('Reservation submission error:', error);
        }
    });
});
