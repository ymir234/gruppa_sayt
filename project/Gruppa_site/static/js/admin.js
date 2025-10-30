// Admin panel JavaScript funksiyalari - Yagona fayl

// Loading spinner funksiyalari
function showLoading() {
    const spinner = document.createElement('div');
    spinner.className = 'loading-spinner';
    spinner.innerHTML = '<div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div>';
    document.body.appendChild(spinner);
}

function hideLoading() {
    const spinner = document.querySelector('.loading-spinner');
    if (spinner) spinner.remove();
}

// Notification funksiyasi
function showNotification(message, type) {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type === 'success' ? 'success' : 'danger'} alert-dismissible fade show`;
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    const mainElement = document.querySelector('main');
    if (mainElement) {
        mainElement.insertBefore(alertDiv, mainElement.firstChild);
    }
    
    setTimeout(() => {
        if (alertDiv.parentElement) {
            alertDiv.remove();
        }
    }, 3000);
}

// Form validation
function initFormValidation() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        const inputs = form.querySelectorAll('input, select, textarea');
        inputs.forEach(input => {
            input.addEventListener('blur', validateField);
            input.addEventListener('input', clearFieldError);
        });
    });
}

function validateField(e) {
    const field = e.target;
    const value = field.value.trim();
    
    // Required field validation
    if (field.hasAttribute('required') && !value) {
        showFieldError(field, 'Bu maydon to\'ldirilishi shart');
        return false;
    }
    
    // Email validation
    if (field.type === 'email' && value) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(value)) {
            showFieldError(field, 'Noto\'g\'ri email formati');
            return false;
        }
    }
    
    // Phone validation
    if (field.name === 'phone' && value) {
        const phoneRegex = /^\+998[0-9]{9}$|^998[0-9]{9}$|^[0-9]{9}$/;
        if (!phoneRegex.test(value)) {
            showFieldError(field, 'Noto\'g\'ri telefon raqami formati');
            return false;
        }
    }
    
    // Clear error if valid
    clearFieldError({ target: field });
    return true;
}

function showFieldError(field, message) {
    field.classList.add('is-invalid');
    field.classList.remove('is-valid');
    
    let feedback = field.parentNode.querySelector('.invalid-feedback');
    if (!feedback) {
        feedback = document.createElement('div');
        feedback.className = 'invalid-feedback';
        field.parentNode.appendChild(feedback);
    }
    feedback.textContent = message;
}

function clearFieldError(e) {
    const field = e.target;
    field.classList.remove('is-invalid');
    
    const feedback = field.parentNode.querySelector('.invalid-feedback');
    if (feedback) {
        feedback.remove();
    }
}

// Yagona delete funksiyasi - barcha turdagi elementlar uchun
function deleteItem(type, id, element) {
    const messages = {
        'student': 'bu talabani',
        'news': 'bu yangilikni', 
        'gallery': 'bu rasmi',
        'schedule': 'bu darsni',
        'admin': 'bu adminni',
        'contact': 'bu aloqa ma\'lumotini'
    };
    
    if (confirm(`Rostan ham ${messages[type]} o\'chirmoqchimisiz?`)) {
        showLoading();
        
        const url = type === 'contact' 
            ? `/admin/delete_contact/${id}`
            : `/admin/delete_${type}/${id}`;
        
        const options = type === 'contact' ? { method: 'DELETE' } : {};
        
        fetch(url, options)
            .then(response => {
                if (type === 'contact') {
                    return response.json().then(data => ({ ok: data.success }));
                }
                return { ok: response.ok };
            })
            .then(({ ok }) => {
                hideLoading();
                if (ok) {
                    showNotification(`${messages[type]} muvaffaqiyatli o\'chirildi!`, 'success');
                    if (element) {
                        element.remove();
                    }
                    // Sahifani yangilash
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showNotification('O\'chirishda xatolik yuz berdi!', 'error');
                }
            })
            .catch(error => {
                hideLoading();
                console.error('Error:', error);
                showNotification('Tarmoq xatosi yuz berdi!', 'error');
            });
    }
}

// Barcha delete tugmalari uchun event listener
document.addEventListener('DOMContentLoaded', function() {
    initFormValidation();
    
    // Barcha form submitlarida validation
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function(e) {
            let isValid = true;
            const inputs = this.querySelectorAll('input, select, textarea');
            
            inputs.forEach(input => {
                if (!validateField({ target: input })) {
                    isValid = false;
                }
            });
            
            if (!isValid) {
                e.preventDefault();
                showNotification('Iltimos, barcha maydonlarni to\'g\'ri to\'ldiring', 'error');
            }
        });
    });

    // Barcha delete tugmalariga event listener qo'shish
    document.addEventListener('click', function(e) {
        if (e.target.closest('.delete-btn')) {
            const button = e.target.closest('.delete-btn');
            const type = button.getAttribute('data-type');
            const id = button.getAttribute('data-id');
            
            if (type && id) {
                e.preventDefault();
                e.stopPropagation();
                
                let element;
                if (type === 'gallery') {
                    element = button.closest('.card.mb-2');
                } else if (type === 'schedule') {
                    element = button.closest('tr');
                } else if (type === 'contact') {
                    element = button.closest('.col-md-6, .col-lg-3');
                } else {
                    element = button.closest('.d-flex.justify-content-between.align-items-center');
                }
                
                deleteItem(type, id, element);
            }
        }
    });

    // Fan va dars turini bog'lash
    const subjectSelect = document.getElementById('subjectSelect');
    const lessonTypeSelect = document.getElementById('lessonTypeSelect');
    
    if (subjectSelect && lessonTypeSelect) {
        subjectSelect.addEventListener('change', function() {
            const subject = this.value;
            lessonTypeSelect.innerHTML = '<option value="">Dars turi</option>';
            
            if (subject === 'Dinshunoslik') {
                lessonTypeSelect.innerHTML += `
                    <option value="Amaliy">Amaliy</option>
                    <option value="Seminar">Seminar</option>
                `;
            } else if (subject && subject !== '') {
                lessonTypeSelect.innerHTML += `
                    <option value="Ma\'ruza">Ma'ruza</option>
                    <option value="Amaliy">Amaliy</option>
                `;
            }
        });
// admin.js ga qo'shing
function initSearch() {
    const searchInput = document.getElementById('globalSearch');
    if (searchInput) {
        searchInput.addEventListener('input', function(e) {
            const searchTerm = e.target.value.toLowerCase();
            
            document.querySelectorAll('.searchable-item').forEach(item => {
                const text = item.textContent.toLowerCase();
                if (text.includes(searchTerm)) {
                    item.style.display = '';
                    // Highlight natijalar
                    highlightText(item, searchTerm);
                } else {
                    item.style.display = 'none';
                }
            });
        });
    }
}

function highlightText(element, term) {
    const innerHTML = element.innerHTML;
    const index = innerHTML.toLowerCase().indexOf(term.toLowerCase());
    if (index >= 0) {
        element.innerHTML = innerHTML.substring(0, index) + 
            '<mark class="search-highlight">' + 
            innerHTML.substring(index, index + term.length) + 
            '</mark>' + 
            innerHTML.substring(index + term.length);
    }
}
        // Formani yuborishdan oldin tekshirish
        const scheduleForm = document.getElementById('scheduleForm');
        if (scheduleForm) {
            scheduleForm.addEventListener('submit', function(e) {
                const day = document.getElementById('daySelect').value;
                const time = document.getElementById('timeSelect').value;
                const subject = document.getElementById('subjectSelect').value;
                const lessonType = document.getElementById('lessonTypeSelect').value;
                const room = document.getElementById('roomSelect')?.value || document.querySelector('input[name="room"]')?.value;
                const teacher = document.getElementById('teacherSelect')?.value || document.querySelector('input[name="teacher"]')?.value;
                
                if (!day || !time || !subject || !lessonType || !room || !teacher) {
                    e.preventDefault();
                    showNotification('Iltimos, barcha maydonlarni to\'ldiring!', 'error');
                    return false;
                }
            });
        }
    }
});
// Edit tugmasi uchun event listener qo'shing
document.addEventListener('click', function(e) {
    if (e.target.closest('.edit-btn')) {
        const button = e.target.closest('.edit-btn');
        const studentId = button.getAttribute('data-id');
        
        if (studentId) {
            e.preventDefault();
            e.stopPropagation();
            window.location.href = `/admin/edit_student/${studentId}`;
        }
    }
});

// Student card hover effekti
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.student-card').forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.querySelector('.student-actions').style.display = 'block';
        });
        
        card.addEventListener('mouseleave', function() {
            this.querySelector('.student-actions').style.display = 'none';
        });
    });
});