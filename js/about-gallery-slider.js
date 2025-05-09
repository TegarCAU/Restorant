document.addEventListener('DOMContentLoaded', function() {
    const aboutGallery = document.querySelector('.about-gallery');
    
    if (aboutGallery) {
        // Gallery images
        const images = [
            {
                src: "https://cdn.antaranews.com/cache/1200x800/2024/09/15/Photo-2-Seribu-Rasa.jpg",
                alt: "Elegant plating of Indonesian cuisine"
            },
            {
                src: "https://media.istockphoto.com/id/516329534/id/foto/jerami-terakhir.jpg?s=612x612&w=0&k=20&c=1m_4S97KrZ6LPBZM_vKGecCs70qWofksa6CjDiWobCk=",
                alt: "Chef preparing Indonesian food"
            },
            {
                src: "https://www.marketeers.com/_next/image/?url=https%3A%2F%2Froom.marketeers.com%2Fwp-content%2Fuploads%2F2023%2F07%2FMG_3908-scaled.jpg&w=1920&q=75",
                alt: "Restaurant interior with Indonesian decor"
            },
            {
                src: "https://www.highstreet.co.id/UserFiles/Image/bariuma/IKP_5792.jpg",
                alt: "Restaurant dining area"
            },
            {src: "https://cdn2.gnfi.net/gnfi/uploads/articles/unique-food-ingredients-only-in-indonesia1472533852.jpg",
                alt: "Indonesian cooking ingredients and spices"
            },
            {
                src: "https://retaildesignblog.net/wp-content/uploads/2018/03/Putu-Made-restaurant-by-Metaphor-Interior-Jakarta-Indonesia-05.jpg",
                alt: "Restaurant dining area"
            },
            {
                src: "https://static.vecteezy.com/system/resources/previews/024/694/356/large_2x/meatball-in-indonesia-known-as-bakso-or-baso-served-with-noodles-vegetables-chili-sauce-in-a-bowl-on-white-background-with-hand-close-up-top-view-flat-lay-free-photo.jpg",
                alt: "Close-up of dish preparation"
            },
            {
                src: "https://images.harpersbazaar.co.id/unsafe/0x0/smart/media/body_8fce2ebaa5d5436380f71dedfa52fba8.jpg",
                alt: "Elegant plating of Indonesian cuisine"
            },
            {
                src: "https://f.hellowork.com/seo/domaine/restauration.jpeg",
                alt: "Chef preparing Indonesian food"
            },
        ];
        
        // Create slider wrapper
        const sliderWrapper = document.createElement('div');
        sliderWrapper.className = 'about-gallery-slider';
        
        // Create slides
        images.forEach((img, index) => {
            const slide = document.createElement('div');
            slide.className = 'about-gallery-slide';
            
            const image = document.createElement('img');
            image.src = img.src;
            image.alt = img.alt;
            
            slide.appendChild(image);
            sliderWrapper.appendChild(slide);
        });
        
        // Create navigation buttons
        const prevButton = document.createElement('button');
        prevButton.className = 'about-gallery-prev';
        prevButton.innerHTML = '&#10094;';
        
        const nextButton = document.createElement('button');
        nextButton.className = 'about-gallery-next';
        nextButton.innerHTML = '&#10095;';
        
        // Replace existing gallery
        aboutGallery.innerHTML = '';
        aboutGallery.appendChild(sliderWrapper);
        aboutGallery.appendChild(prevButton);
        aboutGallery.appendChild(nextButton);
        
        // Slider functionality
        let currentSlide = 0;
        const totalSlides = images.length;
        
        function showSlide(index) {
            const slides = document.querySelectorAll('.about-gallery-slide');
            
            // Reset all slides
            slides.forEach(slide => {
                slide.style.display = 'none';
            });
            
            // Show current slide
            slides[index].style.display = 'block';
        }
        
        // Initial slide
        showSlide(currentSlide);
        
        // Next slide
        nextButton.addEventListener('click', function() {
            currentSlide = (currentSlide + 1) % totalSlides;
            showSlide(currentSlide);
        });
        
        // Previous slide
        prevButton.addEventListener('click', function() {
            currentSlide = (currentSlide - 1 + totalSlides) % totalSlides;
            showSlide(currentSlide);
        });
        
        // Auto-slide every 5 seconds
        setInterval(() => {
            currentSlide = (currentSlide + 1) % totalSlides;
            showSlide(currentSlide);
        }, 5000);
    }
});
