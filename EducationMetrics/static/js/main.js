document.addEventListener('DOMContentLoaded', function() {
    const scanForm = document.getElementById('scanForm');
    
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            const submitButton = this.querySelector('button[type="submit"]');
            submitButton.disabled = true;
            submitButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
        });
    }
});
