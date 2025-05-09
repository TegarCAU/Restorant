// menu data
const menuItems = [
    {
        id: 1,
        name: "Sate Ayam",
        category: "appetizer",
        price: "Rp 50.000",
        description: "Sate ayam dengan bumbu kacang khas",
        image: "https://thumb.viva.co.id/media/frontend/thumbs3/2016/05/03/5727ee73cc978-7-makanan-asli-dari-indonesia-ini-jadi-favoritnya-warga-dunia_665_374.jpg"
    },
    {
        id: 2,
        name: "Rendang Sapi",
        category: "main",
        price: "Rp 120.000",
        description: "Rendang sapi yang lembut dengan bumbu rempah",
        image: "https://cdn0-production-images-kly.akamaized.net/lFL57Veatw1-7kXEFX_rLYoqmAg=/1200x675/smart/filters:quality(75):strip_icc():format(jpeg)/kly-media-production/medias/1697136/original/002803100_1504182506-amazingraze.s3.amazonaws.com1.jpg"
    },
    {
        id: 3,
        name: "Es Campur",
        category: "dessert",
        price: "Rp 35.000",
        description: "Es campur dengan berbagai topping",
        image: "https://asset.kompas.com/crops/mflGKlOsWa44Fb9Xj7KYlIIVQgw=/0x0:1000x667/1200x800/data/photo/2020/04/24/5ea2a3cba9ace.jpg"
    },
    {
        id: 4,
        name: "Opor Telur Ceplok",
        category: "main",
        price: "Rp 35.000",
        description: "Ayam rebus yang diberi bumbu kental dari santan",
        image: "https://i.ytimg.com/vi/CZ0M73T53aE/maxresdefault.jpg"
    },
    {
        id: 5,
        name: "Siomay Ikan",
        category: "appetizer",
        price: "Rp 15.000",
        description: "Terbuat dari daging ikan giling",
        image: "https://notransmilitaryban.org/wp-content/uploads/2025/01/a868c448-68ed-4932-aa3d-0719a2441840.jpeg"
    },
    {
        id: 6,
        name: "Es Teler",
        category: "dessert",
        price: "Rp 40.000",
        description: "terbuat dari potongan buah-buahan seperti alpukat, kelapa muda, dan nangka",
        image: "https://asset.kompas.com/crops/UuCJ6HHkHMVqB-hYmkZrjxA34Ek=/3x0:700x465/1200x800/data/photo/2021/10/23/6173b7b7df5a6.jpg"
    }
];

// Menu Filtering
const filterButtons = document.querySelectorAll('.filter-btn');
const menuGrid = document.getElementById('menuItems');

filterButtons.forEach(button => {
    button.addEventListener('click', () => {
        filterButtons.forEach(btn => btn.classList.remove('active'));
        button.classList.add('active');
        
        const filter = button.dataset.filter;
        displayMenuItems(filter);
    });
});

function displayMenuItems(filter) {
    menuGrid.innerHTML = '';
    
    const filteredItems = filter === 'all' 
        ? menuItems 
        : menuItems.filter(item => item.category === filter);
    
    filteredItems.forEach(item => {
        const menuItem = document.createElement('div');
        menuItem.className = 'menu-item fade-in';
        menuItem.innerHTML = `
            <img src="${item.image}" alt="${item.name}">
            <div class="menu-item-content">
                <h3>${item.name}</h3>
                <p>${item.description}</p>
                <span class="price">${item.price}</span>
            </div>
        `;
        menuGrid.appendChild(menuItem);
    });
}

// Mobile Navigation with smooth animation
const hamburger = document.getElementById('hamburger');
const navLinks = document.querySelector('.nav-links');

hamburger.addEventListener('click', () => {
    hamburger.classList.toggle('active');
    navLinks.classList.toggle('active');
});

// Close mobile menu when clicking a link
document.querySelectorAll('.nav-links a').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const target = document.querySelector(link.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth'
            });
        }
        hamburger.classList.remove('active');
        navLinks.classList.remove('active');

    });
  });


// Reservation Form Validation
const reservationForm = document.getElementById('reservationForm');

reservationForm.addEventListener('submit', (e) => {
    e.preventDefault();
    
    const formData = {
        name: document.getElementById('name').value,
        date: document.getElementById('date').value,
        time: document.getElementById('time').value,
        guests: document.getElementById('guests').value,
        notes: document.getElementById('notes').value
    };

    // Validate form data
    if (!formData.name || !formData.date || !formData.time || !formData.guests) {
        alert('Harap isi semua field yang wajib');
        return;
    }

    // Show success message
    alert('Terima kasih! Reservasi Anda telah diterima.');
    reservationForm.reset();
});

// Smooth Scrolling for Navigation Links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth'
            });
        }
    });
});

// Initialize menu display
displayMenuItems('all');