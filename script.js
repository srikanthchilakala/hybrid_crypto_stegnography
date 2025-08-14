sed / result.capacity) * 100).toFixed(2)}%)
            </div>
            <div class="result-section">
                <strong>Quality Metrics:</strong><br>
                PSNR: ${result.psnr.toFixed(2)} dB
            </div>
            <div class="result-section">
                <strong>Stego Image:</strong><br>
                <img src="${result.stegoImage}" style="max-width: 100%; height: auto; border-radius: 8px; margin-top: 0.5rem;" alt="Steganographic Image">
            </div>
            <div class="result-section">
                <a href="${result.stegoImage}" download="stego_image.png" class="btn btn-outline" style="margin-top: 1rem;">
                    Download Stego Image
                </a>
            </div>
        `;
        
        stegoResult.style.display = 'block';
    }
}

function handleFileSelect(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    // Validate file type
    if (!file.type.startsWith('image/')) {
        showNotification('Please select a valid image file', 'error');
        return;
    }
    
    // Validate file size (10MB limit)
    if (file.size > 10 * 1024 * 1024) {
        showNotification('File size must be less than 10MB', 'error');
        return;
    }
    
    const reader = new FileReader();
    reader.onload = function(e) {
        originalImageData = e.target.result;
        
        // Update drop zone to show preview
        const dropZoneContent = document.getElementById('dropZoneContent');
        if (dropZoneContent) {
            dropZoneContent.innerHTML = `
                <img src="${originalImageData}" style="max-height: 150px; border-radius: 8px;">
                <p>Image loaded successfully</p>
                <button type="button" class="btn btn-outline glow-effect">Change Image</button>
                <small>${file.name} (${(file.size / 1024 / 1024).toFixed(2)} MB)</small>
            `;
        }
        
        // Enable steganography button if SDES is complete
        if (sdesResult) {
            const stegoBtn = document.getElementById('steganographyBtn');
            if (stegoBtn) stegoBtn.disabled = false;
        }
        
        showNotification('Image uploaded successfully!', 'success');
    };
    
    reader.readAsDataURL(file);
}

// ===== DECRYPTION FUNCTIONS =====

function startDecryption() {
    try {
        if (!steganographyResult || !hillCipherResult || !sdesResult) {
            showNotification('Please complete the full encryption process first', 'error');
            return;
        }
        
        // Step 1: Extract message from image
        const steganography = new LSBSteganography();
        steganography.extractMessage(steganographyResult.stegoImage)
            .then(extractedBinary => {
                console.log('Extracted binary:', extractedBinary);
                
                // Step 2: Convert binary to blocks for SDES decryption
                const binaryBlocks = extractedBinary.match(/.{1,8}/g) || [];
                console.log('Binary blocks for SDES:', binaryBlocks);
                
                // Step 3: Decrypt with SDES
                const sdes = new SDES();
                const sdesDecrypted = sdes.decrypt(binaryBlocks, sdesResult.key);
                console.log('SDES decrypted:', sdesDecrypted);
                
                // Step 4: Decrypt with Hill Cipher
                const hillCipher = new HillCipher();
                const finalDecrypted = hillCipher.decrypt(
                    sdesDecrypted,
                    hillCipherResult.keyMatrix,
                    hillCipherResult.originalLength
                );
                console.log('Final decrypted:', finalDecrypted);
                
                // Display result
                displayDecryptionResult(finalDecrypted);
                
                showNotification('Decryption completed successfully!', 'success');
                
            })
            .catch(error => {
                console.error('Decryption Error:', error);
                showNotification(`Decryption Error: ${error.message}`, 'error');
            });
        
    } catch (error) {
        console.error('Decryption Error:', error);
        showNotification(`Decryption Error: ${error.message}`, 'error');
    }
}

function displayDecryptionResult(decryptedText) {
    const decryptResults = document.getElementById('decryptResults');
    const decryptOutput = document.getElementById('decryptOutput');
    
    if (decryptResults && decryptOutput) {
        decryptOutput.innerHTML = `
            <div class="result-section">
                <strong>Decrypted Message:</strong><br>
                <div style="font-size: 1.1rem; margin-top: 0.5rem; padding: 1rem; background: rgba(255, 217, 61, 0.2); border-radius: 8px; border: 1px solid var(--decrypt-primary);">
                    ${decryptedText}
                </div>
            </div>
        `;
        
        decryptResults.style.display = 'block';
    }
}

// ===== UTILITY FUNCTIONS =====

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <span class="notification-message">${message}</span>
            <button class="notification-close" onclick="this.parentElement.parentElement.remove()">×</button>
        </div>
    `;
    
    // Add styles if not already present
    if (!document.querySelector('#notification-styles')) {
        const style = document.createElement('style');
        style.id = 'notification-styles';
        style.textContent = `
            .notification {
                position: fixed;
                top: 2rem;
                right: 2rem;
                max-width: 400px;
                padding: 1rem;
                border-radius: 8px;
                background: var(--card-bg);
                border: 1px solid var(--card-border);
                backdrop-filter: blur(20px);
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
                z-index: 1000;
                animation: slideInNotification 0.3s ease-out;
            }
            
            .notification.success {
                border-color: var(--stego-primary);
                background: rgba(79, 255, 176, 0.1);
            }
            
            .notification.error {
                border-color: #ff6b6b;
                background: rgba(255, 107, 107, 0.1);
            }
            
            .notification-content {
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 1rem;
            }
            
            .notification-message {
                color: var(--text-primary);
                font-size: 0.9rem;
            }
            
            .notification-close {
                background: none;
                border: none;
                color: var(--text-secondary);
                font-size: 1.2rem;
                cursor: pointer;
                padding: 0;
                width: 1.5rem;
                height: 1.5rem;
                display: flex;
                align-items: center;
                justify-content: center;
                border-radius: 50%;
                transition: all 0.2s ease;
            }
            
            .notification-close:hover {
                background: rgba(255, 255, 255, 0.1);
                color: var(--text-primary);
            }
            
            @keyframes slideInNotification {
                from {
                    transform: translateX(100%);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
        `;
        document.head.appendChild(style);
    }
    
    // Add to page
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
}

function exportResults() {
    if (!hillCipherResult && !sdesResult && !steganographyResult) {
        showNotification('No results to export. Please complete the encryption process first.', 'error');
        return;
    }
    
    const exportData = {
        timestamp: new Date().toISOString(),
        hillCipher: hillCipherResult,
        sdes: sdesResult,
        steganography: steganographyResult ? {
            ...steganographyResult,
            stegoImage: '[Base64 Image Data]' // Placeholder to reduce file size
        } : null
    };
    
    const dataStr = JSON.stringify(exportData, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    
    const link = document.createElement('a');
    link.href = URL.createObjectURL(dataBlob);
    link.download = `hybrid-crypto-results-${Date.now()}.json`;
    link.click();
    
    showNotification('Results exported successfully!', 'success');
}

// Text area auto-resize and validation
document.addEventListener('input', function(e) {
    if (e.target.id === 'plainText') {
        const hillBtn = document.getElementById('hillEncryptBtn');
        if (hillBtn) {
            const hasText = e.target.value.trim().length > 0;
            const isMatrixValid = validateMatrix();
            hillBtn.disabled = !hasText || !isMatrixValid;
        }
    }
});

// Add visual feedback for input focus
document.addEventListener('focus', function(e) {
    if (e.target.classList.contains('glow-input')) {
        e.target.parentElement.classList.add('input-focused');
    }
}, true);

document.addEventListener('blur', function(e) {
    if (e.target.classList.contains('glow-input')) {
        e.target.parentElement.classList.remove('input-focused');
    }
}, true);
