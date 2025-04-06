function toggleMenu() {
  const nav = document.getElementById('navLinks');
  nav.style.display = nav.style.display === 'flex' ? 'none' : 'flex';
}

function showInput() {
  const inputSection = document.getElementById('inputSection');
  inputSection.classList.toggle('hidden');
}

function checkUrl() {
  const url = document.getElementById('urlInput').value;
  alert("Analyse de l'URL : " + url); // Placeholder – you can later connect this to a backend
}

// Smooth scroll pour les liens de navigation
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

// Animation du bouton "Commencer"
const ctaButton = document.querySelector('.cta-button');
if (ctaButton) {
    ctaButton.addEventListener('click', () => {
        const analysisSection = document.querySelector('.analysis-section');
        if (analysisSection) {
            analysisSection.scrollIntoView({ behavior: 'smooth' });
        }
    });
}

// Validation de l'URL et gestion de l'analyse
const urlInput = document.getElementById('urlInput');
const analyzeButton = document.querySelector('.analyze-button');

if (urlInput && analyzeButton) {
    analyzeButton.addEventListener('click', () => {
        const url = urlInput.value.trim();
        
        // Validation basique de l'URL
        if (!url) {
            alert('Veuillez entrer une URL à analyser');
            return;
        }

        try {
            new URL(url);
            // Ici, vous pouvez ajouter la logique d'analyse
            alert('Analyse en cours pour : ' + url);
            // La logique d'analyse sera implémentée côté backend
        } catch {
            alert('Veuillez entrer une URL valide');
        }
    });

    // Permettre l'analyse en appuyant sur Entrée
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            analyzeButton.click();
        }
    });
}

// Animation des cartes au scroll
const animateOnScroll = () => {
    const elements = document.querySelectorAll('.feature-card, .test-item, .faq-item');
    
    elements.forEach(element => {
        const elementTop = element.getBoundingClientRect().top;
        const elementBottom = element.getBoundingClientRect().bottom;
        
        if (elementTop < window.innerHeight && elementBottom > 0) {
            element.style.opacity = '1';
            element.style.transform = 'translateY(0)';
        }
    });
};

// Initialisation des animations
document.addEventListener('DOMContentLoaded', () => {
    const elements = document.querySelectorAll('.feature-card, .test-item, .faq-item');
    elements.forEach(element => {
        element.style.opacity = '0';
        element.style.transform = 'translateY(20px)';
        element.style.transition = 'opacity 0.6s ease-out, transform 0.6s ease-out';
    });
    
    animateOnScroll();
});

window.addEventListener('scroll', animateOnScroll);
