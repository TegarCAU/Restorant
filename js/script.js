// Close mobile menu when navigation links are clicked
const mobileNavLinks = document.querySelectorAll('.mobile-nav-link');
mobileNavLinks.forEach(link => {
    link.addEventListener('click', function() {
        const menuBtn = document.querySelector('.mobile-menu-btn');
        const mobileMenu = document.querySelector('.mobile-menu');
        
        menuBtn.classList.remove('active');
        mobileMenu.classList.remove('active');
    });
});// Wait for the DOM to be fully loaded

document.addEventListener('DOMContentLoaded', function() {
    // Mobile menu toggle
    const menuBtn = document.querySelector('.mobile-menu-btn');
    const mobileMenu = document.querySelector('.mobile-menu');
    
    if (menuBtn && mobileMenu) {
        menuBtn.addEventListener('click', function() {
            this.classList.toggle('active');
            mobileMenu.classList.toggle('active');
        });
    }
    
    // Navbar background on scroll
    const navbar = document.querySelector('.navbar');
    
    function updateNavbarBackground() {
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    }
    
    // Initialize navbar state on page load
    updateNavbarBackground();
    
    // Update navbar on scroll
    window.addEventListener('scroll', updateNavbarBackground);
    
    // Smooth scrolling for menu tabs
    const menuTabs = document.querySelectorAll('.menu-tab');
    
    if (menuTabs.length > 0) {
        menuTabs.forEach(tab => {
            tab.addEventListener('click', function(e) {
                e.preventDefault();
                
                // Remove active class from all tabs
                menuTabs.forEach(t => t.classList.remove('active'));
                
                // Add active class to clicked tab
                this.classList.add('active');
                
                // Get the target section ID
                const targetId = this.getAttribute('data-target');
                const targetSection = document.getElementById(targetId);
                
                if (targetSection) {
                    // Scroll to target section with offset for the navbar
                    const navbarHeight = navbar.offsetHeight;
                    const targetPosition = targetSection.offsetTop - navbarHeight - 20;
                    
                    window.scrollTo({
                        top: targetPosition,
                        behavior: 'smooth'
                    });
                }
            });
        });
    }
    
    // Form validation for reservation form
    const reservationForm = document.getElementById('reservation-form');
    
    if (reservationForm) {
        reservationForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Get form inputs
            const name = document.getElementById('name').value.trim();
            const email = document.getElementById('email').value.trim();
            const phone = document.getElementById('phone').value.trim();
            const date = document.getElementById('date').value;
            const time = document.getElementById('time').value;
            const guests = document.getElementById('guests').value;
            
            // Simple validation
            let isValid = true;
            let errorMessages = [];
            
            if (name === '') {
                isValid = false;
                errorMessages.push('Please enter your name');
                document.getElementById('name').classList.add('error');
            }
            
            if (email === '' || !isValidEmail(email)) {
                isValid = false;
                errorMessages.push('Please enter a valid email address');
                document.getElementById('email').classList.add('error');
            }
            
            if (phone === '' || phone.length < 8) {
                isValid = false;
                errorMessages.push('Please enter a valid phone number');
                document.getElementById('phone').classList.add('error');
            }
            
            if (date === '') {
                isValid = false;
                errorMessages.push('Please select a date');
                document.getElementById('date').classList.add('error');
            }
            
            if (time === '') {
                isValid = false;
                errorMessages.push('Please select a time');
                document.getElementById('time').classList.add('error');
            }
            
            if (guests === '') {
                isValid = false;
                errorMessages.push('Please select the number of guests');
                document.getElementById('guests').classList.add('error');
            }
            
            // Show error messages or submit form
            const errorContainer = document.getElementById('form-errors');
            
            if (!isValid && errorContainer) {
                errorContainer.innerHTML = errorMessages.map(msg => `<p>${msg}</p>`).join('');
                errorContainer.style.display = 'block';
            } else if (isValid) {
                // Simulate form submission with a success message
                const successMessage = document.getElementById('form-success');
                if (successMessage) {
                    successMessage.style.display = 'block';
                    errorContainer.style.display = 'none';
                    reservationForm.reset();
                    
                    // Hide success message after 5 seconds
                    setTimeout(function() {
                        successMessage.style.display = 'none';
                    }, 5000);
                }
            }
        });
        
        // Remove error class on input focus
        const formInputs = reservationForm.querySelectorAll('input, select, textarea');
        formInputs.forEach(input => {
            input.addEventListener('focus', function() {
                this.classList.remove('error');
            });
        });
    }
    
    // Helper function to validate email
    function isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }
    
    // Set minimum date for reservation to today
    const dateInput = document.getElementById('date');
    if (dateInput) {
        const today = new Date().toISOString().split('T')[0];
        dateInput.setAttribute('min', today);
    }
    
    // Fade in elements on scroll
    const fadeElements = document.querySelectorAll('.fade-in');
    
    function checkFade() {
        fadeElements.forEach(element => {
            const elementTop = element.getBoundingClientRect().top;
            const elementVisible = 150;
            
            if (elementTop < window.innerHeight - elementVisible) {
                element.classList.add('active');
            }
        });
    }
    
    // Check elements on initial load
    setTimeout(checkFade, 300);
    
    // Check elements on scroll
    window.addEventListener('scroll', checkFade);
});