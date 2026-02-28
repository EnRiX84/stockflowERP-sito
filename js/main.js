/* ============================================
   StockFlow ERP - Main JavaScript
   ============================================ */

document.addEventListener('DOMContentLoaded', () => {

    // ---- Preloader ----
    const preloader = document.getElementById('preloader');
    if (preloader) {
        window.addEventListener('load', () => {
            setTimeout(() => {
                preloader.classList.add('hidden');
            }, 800);
        });
        // Fallback in case load already fired
        setTimeout(() => {
            preloader.classList.add('hidden');
        }, 2000);
    }

    // ---- Navbar Scroll ----
    const navbar = document.getElementById('navbar');
    const handleNavScroll = () => {
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    };
    window.addEventListener('scroll', handleNavScroll, { passive: true });
    handleNavScroll();

    // ---- Mobile Menu ----
    const hamburger = document.getElementById('hamburger');
    const navMenu = document.getElementById('navMenu');

    if (hamburger && navMenu) {
        hamburger.addEventListener('click', () => {
            hamburger.classList.toggle('active');
            navMenu.classList.toggle('open');
            document.body.style.overflow = navMenu.classList.contains('open') ? 'hidden' : '';
        });

        navMenu.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', () => {
                hamburger.classList.remove('active');
                navMenu.classList.remove('open');
                document.body.style.overflow = '';
            });
        });
    }

    // ---- Active Nav Link ----
    const sections = document.querySelectorAll('section[id]');
    const navLinks = document.querySelectorAll('.nav-link');

    const navObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const id = entry.target.getAttribute('id');
                navLinks.forEach(link => {
                    link.classList.toggle('active',
                        link.getAttribute('href') === `#${id}`
                    );
                });
            }
        });
    }, { rootMargin: '-40% 0px -60% 0px' });

    sections.forEach(section => navObserver.observe(section));

    // ---- AOS (Animate on Scroll) ----
    const aosElements = document.querySelectorAll('[data-aos]');

    const aosObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const delay = parseInt(entry.target.getAttribute('data-aos-delay') || '0');
                setTimeout(() => {
                    entry.target.classList.add('aos-animate');
                }, delay);
                aosObserver.unobserve(entry.target);
            }
        });
    }, { threshold: 0.1 });

    aosElements.forEach(el => aosObserver.observe(el));

    // ---- Counters ----
    const counters = document.querySelectorAll('.counter-value');
    let countersAnimated = false;

    const animateCounters = () => {
        if (countersAnimated) return;
        countersAnimated = true;

        counters.forEach(counter => {
            const target = parseFloat(counter.getAttribute('data-count'));
            const decimals = parseInt(counter.getAttribute('data-decimals') || '0');
            const prefix = counter.getAttribute('data-prefix') || '';
            const suffix = counter.getAttribute('data-suffix') || '';
            const duration = 2000;
            const startTime = performance.now();

            const update = (currentTime) => {
                const elapsed = currentTime - startTime;
                const progress = Math.min(elapsed / duration, 1);
                // Ease out cubic
                const eased = 1 - Math.pow(1 - progress, 3);
                const current = target * eased;

                if (decimals > 0) {
                    counter.textContent = prefix + current.toFixed(decimals) + suffix;
                } else {
                    counter.textContent = prefix + Math.round(current) + suffix;
                }

                if (progress < 1) {
                    requestAnimationFrame(update);
                }
            };

            requestAnimationFrame(update);
        });
    };

    const countersSection = document.querySelector('.counters');
    if (countersSection) {
        const counterObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    animateCounters();
                    counterObserver.unobserve(entry.target);
                }
            });
        }, { threshold: 0.3 });

        counterObserver.observe(countersSection);
    }

    // ---- FAQ Accordion ----
    const faqItems = document.querySelectorAll('.faq-item');

    faqItems.forEach(item => {
        const question = item.querySelector('.faq-question');
        const answer = item.querySelector('.faq-answer');

        question.addEventListener('click', () => {
            const isActive = item.classList.contains('active');

            // Close all
            faqItems.forEach(other => {
                other.classList.remove('active');
                other.querySelector('.faq-answer').style.maxHeight = null;
            });

            // Open clicked if it wasn't active
            if (!isActive) {
                item.classList.add('active');
                answer.style.maxHeight = answer.scrollHeight + 'px';
            }
        });
    });

    // ---- Back to Top ----
    const backToTop = document.getElementById('backToTop');
    if (backToTop) {
        window.addEventListener('scroll', () => {
            backToTop.classList.toggle('visible', window.scrollY > 500);
        }, { passive: true });

        backToTop.addEventListener('click', () => {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        });
    }

    // ---- Smooth Scroll ----
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', (e) => {
            const href = anchor.getAttribute('href');
            if (href === '#') return;

            const target = document.querySelector(href);
            if (target) {
                e.preventDefault();
                target.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });

    // ---- Contact Form -> FormSubmit.co ----
    const contactForm = document.getElementById('contactForm');
    const formStatus = document.getElementById('formStatus');
    const submitBtn = document.getElementById('submitBtn');

    if (contactForm) {
        contactForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Invio in corso...';
            formStatus.textContent = '';
            formStatus.className = 'form-status';

            const nome = document.getElementById('nome').value.trim();
            const email = document.getElementById('email').value.trim();
            const negozio = document.getElementById('negozio').value.trim();
            const piano = document.getElementById('piano').value;
            const messaggio = document.getElementById('messaggio').value.trim();

            const data = {
                name: nome,
                email: email,
                _subject: `StockFlow - Contatto da ${nome}${negozio ? ` (${negozio})` : ''}`,
                message: messaggio,
                negozio: negozio || 'Non specificato',
                piano: piano || 'Non specificato',
            };

            try {
                const response = await fetch('https://formsubmit.co/ajax/carusoenricom@gmail.com', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify(data)
                });

                if (response.ok) {
                    formStatus.textContent = 'Messaggio inviato con successo! Ti risponderemo al più presto.';
                    formStatus.className = 'form-status success';
                    contactForm.reset();
                } else {
                    throw new Error('Errore invio');
                }
            } catch {
                formStatus.textContent = 'Si è verificato un errore. Riprova o scrivici direttamente a carusoenricom@gmail.com';
                formStatus.className = 'form-status error';
            } finally {
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="fas fa-paper-plane"></i> Invia Messaggio';
            }
        });
    }

    // ---- Hero Particles ----
    const canvas = document.getElementById('heroParticles');
    if (canvas) {
        const ctx = canvas.getContext('2d');
        let particles = [];
        let animId;

        const resize = () => {
            const hero = canvas.parentElement;
            canvas.width = hero.offsetWidth;
            canvas.height = hero.offsetHeight;
        };

        const colors = [
            'rgba(37, 99, 235, 0.3)',   // blue
            'rgba(13, 148, 136, 0.3)',   // teal
            'rgba(249, 115, 22, 0.2)',   // orange
            'rgba(96, 165, 250, 0.2)',   // light blue
            'rgba(45, 212, 191, 0.2)',   // light teal
        ];

        const shapes = ['circle', 'square', 'triangle'];

        class Particle {
            constructor() {
                this.reset();
            }

            reset() {
                this.x = Math.random() * canvas.width;
                this.y = Math.random() * canvas.height;
                this.size = Math.random() * 4 + 2;
                this.speedX = (Math.random() - 0.5) * 0.5;
                this.speedY = (Math.random() - 0.5) * 0.5;
                this.color = colors[Math.floor(Math.random() * colors.length)];
                this.shape = shapes[Math.floor(Math.random() * shapes.length)];
                this.rotation = Math.random() * Math.PI * 2;
                this.rotationSpeed = (Math.random() - 0.5) * 0.02;
            }

            update() {
                this.x += this.speedX;
                this.y += this.speedY;
                this.rotation += this.rotationSpeed;

                if (this.x < -20 || this.x > canvas.width + 20 ||
                    this.y < -20 || this.y > canvas.height + 20) {
                    this.reset();
                }
            }

            draw() {
                ctx.save();
                ctx.translate(this.x, this.y);
                ctx.rotate(this.rotation);
                ctx.fillStyle = this.color;

                if (this.shape === 'circle') {
                    ctx.beginPath();
                    ctx.arc(0, 0, this.size, 0, Math.PI * 2);
                    ctx.fill();
                } else if (this.shape === 'square') {
                    ctx.fillRect(-this.size, -this.size, this.size * 2, this.size * 2);
                } else {
                    ctx.beginPath();
                    ctx.moveTo(0, -this.size);
                    ctx.lineTo(this.size, this.size);
                    ctx.lineTo(-this.size, this.size);
                    ctx.closePath();
                    ctx.fill();
                }

                ctx.restore();
            }
        }

        const init = () => {
            resize();
            const count = Math.min(40, Math.floor(canvas.width / 30));
            particles = [];
            for (let i = 0; i < count; i++) {
                particles.push(new Particle());
            }
        };

        const animate = () => {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            particles.forEach(p => {
                p.update();
                p.draw();
            });
            animId = requestAnimationFrame(animate);
        };

        init();
        animate();

        window.addEventListener('resize', () => {
            cancelAnimationFrame(animId);
            init();
            animate();
        });
    }

    // === Dynamic News from JSON ===
    const newsGrid = document.getElementById('news-grid');
    if (newsGrid) {
        fetch('data/notizie.json')
            .then(r => r.json())
            .then(notizie => {
                if (!notizie || notizie.length === 0) {
                    const newsSection = document.getElementById('news');
                    if (newsSection) newsSection.style.display = 'none';
                    return;
                }
                const categoryColors = {
                    'aggiornamento': '#2563EB',
                    'funzionalita': '#0D9488',
                    'evento': '#F97316',
                    'novita': '#8B5CF6'
                };
                newsGrid.innerHTML = notizie.map((n, i) => {
                    const color = categoryColors[n.categoria] || '#2563EB';
                    const data = n.data || '';
                    return `
                    <div class="news-card" data-aos="fade-up" data-aos-delay="${i * 100}" style="background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.07);transition:transform 0.3s,box-shadow 0.3s;border:1px solid #f0f0f0">
                        <div style="height:6px;background:${color}"></div>
                        <div style="padding:28px">
                            <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
                                <span style="background:${color}10;color:${color};padding:4px 12px;border-radius:20px;font-size:0.75rem;font-weight:600;text-transform:uppercase">${n.categoria}</span>
                                ${data ? `<span style="color:#94a3b8;font-size:0.8rem"><i class="fas fa-calendar-alt" style="margin-right:4px"></i>${data}</span>` : ''}
                            </div>
                            <h3 style="font-size:1.15rem;font-weight:700;color:#1e293b;margin-bottom:10px;line-height:1.4">${n.titolo}</h3>
                            <p style="color:#64748b;font-size:0.92rem;line-height:1.6;margin-bottom:16px">${n.descrizione || ''}</p>
                            ${n.links && n.links.length > 0 ? n.links.map(l => `<a href="${l.url}" target="_blank" rel="noopener" style="color:${color};font-weight:600;font-size:0.9rem;text-decoration:none;display:inline-flex;align-items:center;gap:6px;margin-right:16px">${l.testo} <i class="fas fa-arrow-right" style="font-size:0.75rem"></i></a>`).join('') : ''}
                        </div>
                    </div>`;
                }).join('');
                // Re-observe AOS for dynamically added elements
                newsGrid.querySelectorAll('[data-aos]').forEach(el => {
                    if (typeof aosObserver !== 'undefined') aosObserver.observe(el);
                });
            })
            .catch(() => {
                const newsSection = document.getElementById('news');
                if (newsSection) newsSection.style.display = 'none';
            });
    }

});
