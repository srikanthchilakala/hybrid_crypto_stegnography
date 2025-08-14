// Hybrid Cryptographic System - Complete Implementation
// Hill Cipher + SDES + Steganography

// ===== GLOBAL STATE =====
let currentStep = 1;
let hillCipherResult = null;
let sdesResult = null;
let steganographyResult = null;
let originalImageData = null;

// ===== CRYPTOGRAPHIC UTILITY FUNCTIONS =====

// Text to Binary Conversion
function textToBinary(text) {
    return text
        .split('')
        .map(char => char.charCodeAt(0).toString(2).padStart(8, '0'))
        .join('');
}

function binaryToText(binary) {
    const chunks = binary.match(/.{1,8}/g) || [];
    return chunks
        .map(chunk => String.fromCharCode(parseInt(chunk, 2)))
        .join('');
}

function stringTo8BitBlocks(text) {
    const binary = textToBinary(text);
    const blocks = [];
    for (let i = 0; i < binary.length; i += 8) {
        blocks.push(binary.slice(i, i + 8).padEnd(8, '0'));
    }
    return blocks;
}

function blocksToString(blocks) {
    const binary = blocks.join('');
    return binaryToText(binary);
}

// Mathematical Utility Functions
function mod(n, m) {
    return ((n % m) + m) % m;
}

function modInverse(a, m) {
    for (let i = 1; i < m; i++) {
        if ((a * i) % m === 1) {
            return i;
        }
    }
    throw new Error(`Modular inverse of ${a} mod ${m} does not exist`);
}

function matrixDeterminant2x2(matrix) {
    return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0];
}

function matrixInverse2x2(matrix, modulus = 26) {
    const det = matrixDeterminant2x2(matrix);
    const detInv = modInverse(mod(det, modulus), modulus);
    
    return [
        [mod(matrix[1][1] * detInv, modulus), mod(-matrix[0][1] * detInv, modulus)],
        [mod(-matrix[1][0] * detInv, modulus), mod(matrix[0][0] * detInv, modulus)]
    ];
}

function validateMatrix2x2(matrix, modulus = 26) {
    const det = matrixDeterminant2x2(matrix);
    try {
        modInverse(mod(det, modulus), modulus);
        return true;
    } catch {
        return false;
    }
}

// ===== HILL CIPHER IMPLEMENTATION =====
class HillCipher {
    constructor() {
        this.ALPHABET_SIZE = 26;
    }
    
    charToNum(char) {
        return char.toUpperCase().charCodeAt(0) - 65;
    }
    
    numToChar(num) {
        return String.fromCharCode(mod(num, this.ALPHABET_SIZE) + 65);
    }
    
    preprocessText(text) {
        // Remove non-alphabetic characters and convert to uppercase
        let processed = text.replace(/[^A-Za-z]/g, '').toUpperCase();
        
        // Pad with 'X' if odd length for 2x2 matrix
        if (processed.length % 2 !== 0) {
            processed += 'X';
        }
        
        return processed;
    }
    
    textToBinaryBlocks(text) {
        return text.split('').map(char => 
            char.charCodeAt(0).toString(2).padStart(8, '0')
        );
    }
    
    encrypt(plainText, keyMatrix) {
        if (!validateMatrix2x2(keyMatrix, this.ALPHABET_SIZE)) {
            throw new Error('Invalid key matrix: determinant must be coprime with 26');
        }
        
        // Store original length for proper decryption
        const originalText = plainText.replace(/[^A-Za-z]/g, '').toUpperCase();
        const originalLength = originalText.length;
        
        const processedText = this.preprocessText(plainText);
        let encryptedText = '';
        
        // Process text in pairs
        for (let i = 0; i < processedText.length; i += 2) {
            const char1 = this.charToNum(processedText[i]);
            const char2 = this.charToNum(processedText[i + 1]);
            
            // Matrix multiplication
            const encrypted1 = mod(keyMatrix[0][0] * char1 + keyMatrix[0][1] * char2, this.ALPHABET_SIZE);
            const encrypted2 = mod(keyMatrix[1][0] * char1 + keyMatrix[1][1] * char2, this.ALPHABET_SIZE);
            
            encryptedText += this.numToChar(encrypted1) + this.numToChar(encrypted2);
        }
        
        const binaryBlocks = this.textToBinaryBlocks(encryptedText);
        
        return {
            plainText: processedText,
            originalText: originalText,
            originalLength: originalLength,
            encryptedText,
            keyMatrix,
            binaryBlocks
        };
    }
    
    decrypt(encryptedText, keyMatrix, originalLength = null) {
        if (!validateMatrix2x2(keyMatrix, this.ALPHABET_SIZE)) {
            throw new Error('Invalid key matrix: determinant must be coprime with 26');
        }
        
        console.log('Hill Decrypt - Input:', encryptedText, 'Original Length:', originalLength);
        
        const inverseMatrix = matrixInverse2x2(keyMatrix, this.ALPHABET_SIZE);
        let decryptedText = '';
        
        // Process text in pairs
        for (let i = 0; i < encryptedText.length; i += 2) {
            const char1 = this.charToNum(encryptedText[i]);
            const char2 = this.charToNum(encryptedText[i + 1]);
            
            // Matrix multiplication with inverse
            const decrypted1 = mod(inverseMatrix[0][0] * char1 + inverseMatrix[0][1] * char2, this.ALPHABET_SIZE);
            const decrypted2 = mod(inverseMatrix[1][0] * char1 + inverseMatrix[1][1] * char2, this.ALPHABET_SIZE);
            
            decryptedText += this.numToChar(decrypted1) + this.numToChar(decrypted2);
        }
        
        console.log('Hill Decrypt - Before padding removal:', decryptedText);
        
        // Remove padding if original length is provided
        if (originalLength !== null && originalLength > 0 && originalLength < decryptedText.length) {
            // Remove trailing padding to match original length
            decryptedText = decryptedText.substring(0, originalLength);
            console.log('Hill Decrypt - After padding removal:', decryptedText);
        }
        
        return decryptedText;
    }
}

// ===== SDES IMPLEMENTATION =====
class SDES {
    constructor() {
        // S-DES Permutation tables
        this.P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6];
        this.P8 = [6, 3, 7, 4, 8, 5, 10, 9];
        this.IP = [2, 6, 3, 1, 4, 8, 5, 7];
        this.IP_INV = [4, 1, 3, 5, 7, 2, 8, 6];
        this.EP = [4, 1, 2, 3, 2, 3, 4, 1];
        this.P4 = [2, 4, 3, 1];
        
        this.S0 = [
            [1, 0, 3, 2],
            [3, 2, 1, 0],
            [0, 2, 1, 3],
            [3, 1, 3, 2]
        ];
        
        this.S1 = [
            [0, 1, 2, 3],
            [2, 0, 1, 3],
            [3, 0, 1, 0],
            [2, 1, 0, 3]
        ];
    }
    
    permute(input, table) {
        return table.map(pos => input[pos - 1]).join('');
    }
    
    leftShift(bits, shifts) {
        return bits.slice(shifts) + bits.slice(0, shifts);
    }
    
    generateSubKeys(key) {
        if (key.length !== 10) {
            throw new Error('Key must be 10 bits long');
        }
        
        // Apply P10 permutation
        const p10Result = this.permute(key, this.P10);
        
        // Split into two 5-bit halves
        const left1 = p10Result.slice(0, 5);
        const right1 = p10Result.slice(5);
        
        // Left shift by 1 for K1
        const left1Shifted = this.leftShift(left1, 1);
        const right1Shifted = this.leftShift(right1, 1);
        const k1 = this.permute(left1Shifted + right1Shifted, this.P8);
        
        // Left shift by 2 more (total 3) for K2
        const left2Shifted = this.leftShift(left1Shifted, 2);
        const right2Shifted = this.leftShift(right1Shifted, 2);
        const k2 = this.permute(left2Shifted + right2Shifted, this.P8);
        
        return { k1, k2 };
    }
    
    sBoxLookup(input, sBox) {
        const row = parseInt(input[0] + input[3], 2);
        const col = parseInt(input[1] + input[2], 2);
        return sBox[row][col].toString(2).padStart(2, '0');
    }
    
    fFunction(right, subKey) {
        // Expansion permutation
        const expanded = this.permute(right, this.EP);
        
        // XOR with subkey
        const xored = expanded.split('').map((bit, i) => 
            (parseInt(bit) ^ parseInt(subKey[i])).toString()
        ).join('');
        
        // S-box substitution
        const left4 = xored.slice(0, 4);
        const right4 = xored.slice(4);
        
        const s0Result = this.sBoxLookup(left4, this.S0);
        const s1Result = this.sBoxLookup(right4, this.S1);
        
        // P4 permutation
        return this.permute(s0Result + s1Result, this.P4);
    }
    
    encryptBlock(block, k1, k2) {
        if (block.length !== 8) {
            throw new Error('Block must be 8 bits long');
        }
        
        // Initial permutation
        const ipResult = this.permute(block, this.IP);
        
        // Split into left and right halves
        let left = ipResult.slice(0, 4);
        let right = ipResult.slice(4);
        
        // Round 1
        const fResult1 = this.fFunction(right, k1);
        const newLeft = right;
        const newRight = left.split('').map((bit, i) => 
            (parseInt(bit) ^ parseInt(fResult1[i])).toString()
        ).join('');
        
        left = newLeft;
        right = newRight;
        
        // Round 2
        const fResult2 = this.fFunction(right, k2);
        const finalLeft = left.split('').map((bit, i) => 
            (parseInt(bit) ^ parseInt(fResult2[i])).toString()
        ).join('');
        const finalRight = right;
        
        // Final permutation (inverse of IP)
        return this.permute(finalLeft + finalRight, this.IP_INV);
    }
    
    decryptBlock(block, k1, k2) {
        // Decryption is the same as encryption but with subkeys swapped
        return this.encryptBlock(block, k2, k1);
    }
    
    encrypt(text, key) {
        const blocks = stringTo8BitBlocks(text);
        const subKeys = this.generateSubKeys(key);
        
        const encryptedBlocks = blocks.map(block => 
            this.encryptBlock(block, subKeys.k1, subKeys.k2)
        );
        
        return {
            input: blocks,
            output: encryptedBlocks,
            key,
            subKeys
        };
    }
    
    decrypt(blocks, key) {
        const subKeys = this.generateSubKeys(key);
        
        const decryptedBlocks = blocks.map(block => 
            this.decryptBlock(block, subKeys.k1, subKeys.k2)
        );
        
        return blocksToString(decryptedBlocks);
    }
}

// ===== LSB STEGANOGRAPHY IMPLEMENTATION =====
class LSBSteganography {
    constructor() {
        this.canvas = document.createElement('canvas');
        this.ctx = this.canvas.getContext('2d');
    }
    
    imageDataToCanvas(imageData) {
        return new Promise((resolve, reject) => {
            const img = new Image();
            img.onload = () => {
                this.canvas.width = img.width;
                this.canvas.height = img.height;
                this.ctx.drawImage(img, 0, 0);
                resolve(this.ctx.getImageData(0, 0, img.width, img.height));
            };
            img.onerror = reject;
            img.src = imageData;
        });
    }
    
    canvasToImageData() {
        return this.canvas.toDataURL('image/png');
    }
    
    textToBinary(text) {
        return text.split('').map(char => 
            char.charCodeAt(0).toString(2).padStart(8, '0')
        ).join('');
    }
    
    binaryToText(binary) {
        const chunks = binary.match(/.{1,8}/g) || [];
        return chunks.map(chunk => 
            String.fromCharCode(parseInt(chunk, 2))
        ).join('');
    }
    
    calculatePSNR(original, modified) {
        let mse = 0;
        const totalPixels = original.width * original.height;
        
        for (let i = 0; i < original.data.length; i += 4) {
            const rDiff = original.data[i] - modified.data[i];
            const gDiff = original.data[i + 1] - modified.data[i + 1];
            const bDiff = original.data[i + 2] - modified.data[i + 2];
            
            mse += (rDiff * rDiff + gDiff * gDiff + bDiff * bDiff) / 3;
        }
        
        mse /= totalPixels;
        
        if (mse === 0) return Infinity;
        return 20 * Math.log10(255 / Math.sqrt(mse));
    }
    
    async hideMessage(imageData, message) {
        const originalImageData = await this.imageDataToCanvas(imageData);
        const modifiedImageData = new ImageData(
            new Uint8ClampedArray(originalImageData.data),
            originalImageData.width,
            originalImageData.height
        );
        
        // Convert message to binary and add delimiter
        const messageBinary = this.textToBinary(message);
        const delimiter = '1111111111111110'; // 16-bit delimiter
        const fullMessage = messageBinary + delimiter;
        
        console.log('Hiding message:', message);
        console.log('Message binary length:', messageBinary.length);
        console.log('Total capacity needed:', fullMessage.length);
        
        // Check if image has enough capacity
        const maxCapacity = Math.floor((originalImageData.data.length / 4) * 3); // RGB channels only
        if (fullMessage.length > maxCapacity) {
            throw new Error(`Image too small. Need ${fullMessage.length} bits, but image can only hold ${maxCapacity} bits.`);
        }
        
        // Hide message in LSBs
        let messageIndex = 0;
        for (let i = 0; i < modifiedImageData.data.length && messageIndex < fullMessage.length; i += 4) {
            // Modify R, G, B channels (skip Alpha)
            for (let j = 0; j < 3 && messageIndex < fullMessage.length; j++) {
                const pixelValue = modifiedImageData.data[i + j];
                const messageBit = parseInt(fullMessage[messageIndex]);
                
                // Clear LSB and set to message bit
                modifiedImageData.data[i + j] = (pixelValue & 0xFE) | messageBit;
                messageIndex++;
            }
        }
        
        // Put modified image data back to canvas
        this.ctx.putImageData(modifiedImageData, 0, 0);
        
        // Calculate PSNR
        const psnr = this.calculatePSNR(originalImageData, modifiedImageData);
        
        return {
            originalImage: imageData,
            stegoImage: this.canvasToImageData(),
            message: message,
            messageBinary: messageBinary,
            capacity: maxCapacity,
            used: fullMessage.length,
            psnr: psnr,
            imageSize: {
                width: originalImageData.width,
                height: originalImageData.height
            }
        };
    }
    
    async extractMessage(imageData) {
        const stegoImageData = await this.imageDataToCanvas(imageData);
        
        // Extract bits from LSBs
        let extractedBinary = '';
        const delimiter = '1111111111111110';
        
        for (let i = 0; i < stegoImageData.data.length; i += 4) {
            // Extract from R, G, B channels
            for (let j = 0; j < 3; j++) {
                const lsb = stegoImageData.data[i + j] & 1;
                extractedBinary += lsb.toString();
                
                // Check for delimiter
                if (extractedBinary.length >= delimiter.length) {
                    const lastBits = extractedBinary.slice(-delimiter.length);
                    if (lastBits === delimiter) {
                        // Found delimiter, extract message
                        const messageBinary = extractedBinary.slice(0, -delimiter.length);
                        return this.binaryToText(messageBinary);
                    }
                }
            }
        }
        
        throw new Error('No hidden message found or delimiter not detected');
    }
}

// ===== UI MANAGEMENT =====

// Initialize UI on page load
document.addEventListener('DOMContentLoaded', function() {
    initializeUI();
    setupEventListeners();
    updateStepIndicator();
    validateMatrix();
});

function initializeUI() {
    // Generate step indicator
    const stepIndicator = document.getElementById('stepIndicator');
    const steps = [
        { number: 1, title: 'Hill Cipher', description: 'Matrix Encryption' },
        { number: 2, title: 'Binary Conversion', description: 'Text to Binary' },
        { number: 3, title: 'SDES Encryption', description: 'Block Cipher' },
        { number: 4, title: 'Binary Processing', description: 'Bit Manipulation' },
        { number: 5, title: 'Image Upload', description: 'Cover Selection' },
        { number: 6, title: 'Steganography', description: 'LSB Embedding' },
        { number: 7, title: 'Verification', description: 'Quality Check' },
        { number: 8, title: 'Complete', description: 'Export Results' }
    ];
    
    stepIndicator.innerHTML = steps.map(step => `
        <div class="step-item ${step.number === 1 ? 'active' : ''}" data-step="${step.number}">
            <div class="step-number">${step.number}</div>
            <div class="step-title">${step.title}</div>
            <div class="step-desc">${step.description}</div>
        </div>
    `).join('');
    
    // Set initial progress
    updateProgress(0);
}

function setupEventListeners() {
    // Matrix input validation
    const matrixInputs = document.querySelectorAll('.matrix-input');
    matrixInputs.forEach(input => {
        input.addEventListener('input', validateMatrix);
    });
    
    // Binary key input validation
    const bitInputs = document.querySelectorAll('.bit-input');
    bitInputs.forEach((input, index) => {
        input.addEventListener('input', function(e) {
            // Only allow 0 and 1
            if (e.target.value !== '0' && e.target.value !== '1') {
                e.target.value = '';
            }
            validateSDESKey();
        });
        
        // Auto-focus next input
        input.addEventListener('input', function() {
            if (this.value && index < bitInputs.length - 1) {
                bitInputs[index + 1].focus();
            }
        });
    });
    
    // File upload handling
    const fileInput = document.getElementById('imageInput');
    const dropZone = document.getElementById('fileDropZone');
    const dropZoneContent = document.getElementById('dropZoneContent');
    
    fileInput.addEventListener('change', handleFileSelect);
    
    dropZone.addEventListener('click', () => fileInput.click());
    
    dropZone.addEventListener('dragover', function(e) {
        e.preventDefault();
        this.classList.add('dragover');
    });
    
    dropZone.addEventListener('dragleave', function(e) {
        e.preventDefault();
        this.classList.remove('dragover');
    });
    
    dropZone.addEventListener('drop', function(e) {
        e.preventDefault();
        this.classList.remove('dragover');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFileSelect({ target: { files: files } });
        }
    });
}

function updateStepIndicator() {
    const stepItems = document.querySelectorAll('.step-item');
    const stepDescription = document.getElementById('stepDescription');
    
    stepItems.forEach((item, index) => {
        item.classList.remove('active', 'completed');
        if (index + 1 < currentStep) {
            item.classList.add('completed');
        } else if (index + 1 === currentStep) {
            item.classList.add('active');
        }
    });
    
    // Update progress description
    const descriptions = [
        'Step 1 of 8 - Hill Cipher Encryption',
        'Step 2 of 8 - Binary Conversion',
        'Step 3 of 8 - SDES Encryption',
        'Step 4 of 8 - Binary Processing',
        'Step 5 of 8 - Image Upload',
        'Step 6 of 8 - Steganography',
        'Step 7 of 8 - Verification',
        'Step 8 of 8 - Process Complete'
    ];
    
    if (stepDescription) {
        stepDescription.textContent = descriptions[currentStep - 1] || descriptions[0];
    }
    
    updateProgress((currentStep - 1) / 7 * 100);
}

function updateProgress(percentage) {
    const progressFill = document.getElementById('progressFill');
    if (progressFill) {
        progressFill.style.width = `${percentage}%`;
    }
}

function validateMatrix() {
    const matrix = getKeyMatrix();
    const det = matrixDeterminant2x2(matrix);
    const isValid = validateMatrix2x2(matrix, 26);
    
    const determinantSpan = document.getElementById('matrixDeterminant');
    const validationBadge = document.getElementById('matrixValidation');
    
    if (determinantSpan) {
        determinantSpan.textContent = `Determinant: ${det} (mod 26: ${mod(det, 26)})`;
    }
    
    if (validationBadge) {
        validationBadge.textContent = isValid ? 'Valid' : 'Invalid';
        validationBadge.className = `badge ${isValid ? 'valid' : 'invalid'} animated-badge`;
    }
    
    // Enable/disable Hill cipher button
    const hillBtn = document.getElementById('hillEncryptBtn');
    if (hillBtn) {
        hillBtn.disabled = !isValid || !document.getElementById('plainText').value.trim();
    }
    
    return isValid;
}

function validateSDESKey() {
    const bitInputs = document.querySelectorAll('.bit-input');
    let isValid = true;
    
    bitInputs.forEach(input => {
        if (input.value !== '0' && input.value !== '1') {
            isValid = false;
        }
    });
    
    return isValid;
}

function getKeyMatrix() {
    return [
        [
            parseInt(document.getElementById('matrix00').value) || 0,
            parseInt(document.getElementById('matrix01').value) || 0
        ],
        [
            parseInt(document.getElementById('matrix10').value) || 0,
            parseInt(document.getElementById('matrix11').value) || 0
        ]
    ];
}

function getSDESKey() {
    const bitInputs = document.querySelectorAll('.bit-input');
    return Array.from(bitInputs).map(input => input.value).join('');
}

// ===== ENCRYPTION FUNCTIONS =====

function encryptHillCipher() {
    try {
        const plainText = document.getElementById('plainText').value.trim();
        if (!plainText) {
            showNotification('Please enter a message to encrypt', 'error');
            return;
        }
        
        const keyMatrix = getKeyMatrix();
        if (!validateMatrix2x2(keyMatrix, 26)) {
            showNotification('Invalid key matrix. Please check your matrix values.', 'error');
            return;
        }
        
        const hillCipher = new HillCipher();
        hillCipherResult = hillCipher.encrypt(plainText, keyMatrix);
        
        console.log('Hill Cipher Result:', hillCipherResult);
        
        // Display result
        displayHillResult(hillCipherResult);
        
        // Enable next step
        enableSDES();
        currentStep = 2;
        updateStepIndicator();
        updateProcessFlow('hill', 'completed');
        updateProcessFlow('sdes', 'active');
        
        showNotification('Hill Cipher encryption completed successfully!', 'success');
        
    } catch (error) {
        console.error('Hill Cipher Error:', error);
        showNotification(`Hill Cipher Error: ${error.message}`, 'error');
    }
}

function encryptSDES() {
    try {
        if (!hillCipherResult) {
            showNotification('Please complete Hill Cipher encryption first', 'error');
            return;
        }
        
        const sdesKey = getSDESKey();
        if (!validateSDESKey()) {
            showNotification('Invalid SDES key. Please ensure all bits are 0 or 1.', 'error');
            return;
        }
        
        const sdes = new SDES();
        sdesResult = sdes.encrypt(hillCipherResult.encryptedText, sdesKey);
        
        console.log('SDES Result:', sdesResult);
        
        // Display result
        displaySDESResult(sdesResult);
        
        // Enable next step
        enableSteganography();
        currentStep = 5; // Skip to image upload step
        updateStepIndicator();
        updateProcessFlow('sdes', 'completed');
        updateProcessFlow('stego', 'active');
        
        showNotification('SDES encryption completed successfully!', 'success');
        
    } catch (error) {
        console.error('SDES Error:', error);
        showNotification(`SDES Error: ${error.message}`, 'error');
    }
}

function hideInImage() {
    try {
        if (!sdesResult || !originalImageData) {
            showNotification('Please complete SDES encryption and upload an image first', 'error');
            return;
        }
        
        const steganography = new LSBSteganography();
        const binaryMessage = sdesResult.output.join('');
        
        steganography.hideMessage(originalImageData, binaryMessage)
            .then(result => {
                steganographyResult = result;
                console.log('Steganography Result:', steganographyResult);
                
                // Display result
                displaySteganographyResult(steganographyResult);
                
                // Complete process
                currentStep = 8;
                updateStepIndicator();
                updateProcessFlow('stego', 'completed');
                enableDecryption();
                
                showNotification('Message hidden in image successfully!', 'success');
            })
            .catch(error => {
                console.error('Steganography Error:', error);
                showNotification(`Steganography Error: ${error.message}`, 'error');
            });
        
    } catch (error) {
        console.error('Steganography Error:', error);
        showNotification(`Steganography Error: ${error.message}`, 'error');
    }
}

// ===== UI HELPER FUNCTIONS =====

function enableSDES() {
    const sdesCard = document.getElementById('sdesCard');
    const sdesBtn = document.getElementById('sdesEncryptBtn');
    const sdesStepNumber = sdesCard.querySelector('.step-number');
    
    sdesCard.classList.remove('disabled');
    sdesBtn.disabled = false;
    sdesStepNumber.classList.remove('disabled');
}

function enableSteganography() {
    const stegoCard = document.getElementById('steganographyCard');
    const stegoBtn = document.getElementById('steganographyBtn');
    const stegoStepNumber = stegoCard.querySelector('.step-number');
    
    stegoCard.classList.remove('disabled');
    if (originalImageData) {
        stegoBtn.disabled = false;
    }
    stegoStepNumber.classList.remove('disabled');
}

function enableDecryption() {
    const decryptBtn = document.getElementById('decryptBtn');
    if (decryptBtn) {
        decryptBtn.disabled = false;
    }
}

function updateProcessFlow(step, status) {
    const flowSteps = {
        'hill': document.getElementById('flowStep1'),
        'sdes': document.getElementById('flowStep2'),
        'stego': document.getElementById('flowStep3')
    };
    
    if (flowSteps[step]) {
        const statusElement = flowSteps[step].querySelector('.flow-status');
        flowSteps[step].className = `flow-step ${step}-flow ${status}`;
        
        const statusTexts = {
            'ready': 'Ready',
            'active': 'Processing',
            'completed': 'Complete',
            'waiting': 'Waiting'
        };
        
        if (statusElement) {
            statusElement.textContent = statusTexts[status] || status;
        }
    }
}

function displayHillResult(result) {
    const hillResult = document.getElementById('hillResult');
    const hillOutput = document.getElementById('hillOutput');
    const emptyState = document.getElementById('emptyState');
    
    if (hillResult && hillOutput) {
        hillOutput.innerHTML = `
            <div class="result-section">
                <strong>Original Text:</strong> ${result.originalText}
            </div>
            <div class="result-section">
                <strong>Processed Text:</strong> ${result.plainText}
            </div>
            <div class="result-section">
                <strong>Encrypted Text:</strong> ${result.encryptedText}
            </div>
            <div class="result-section">
                <strong>Binary Blocks:</strong><br>
                <div class="binary-display">${result.binaryBlocks.join(' ')}</div>
            </div>
        `;
        
        hillResult.style.display = 'block';
        if (emptyState) emptyState.style.display = 'none';
    }
}

function displaySDESResult(result) {
    const sdesResult = document.getElementById('sdesResult');
    const sdesOutput = document.getElementById('sdesOutput');
    
    if (sdesResult && sdesOutput) {
        sdesOutput.innerHTML = `
            <div class="result-section">
                <strong>Input Blocks:</strong><br>
                <div class="binary-display">${result.input.join(' ')}</div>
            </div>
            <div class="result-section">
                <strong>SDES Key:</strong> ${result.key}
            </div>
            <div class="result-section">
                <strong>Subkeys:</strong> K1: ${result.subKeys.k1}, K2: ${result.subKeys.k2}
            </div>
            <div class="result-section">
                <strong>Encrypted Blocks:</strong><br>
                <div class="binary-display">${result.output.join(' ')}</div>
            </div>
        `;
        
        sdesResult.style.display = 'block';
    }
}

function displaySteganographyResult(result) {
    const stegoResult = document.getElementById('stegoResult');
    const stegoPreview = document.getElementById('stegoPreview');
    
    if (stegoResult && stegoPreview) {
        stegoPreview.innerHTML = `
            <div class="result-section">
                <strong>Image Information:</strong><br>
                Size: ${result.imageSize.width} × ${result.imageSize.height}<br>
                Capacity: ${result.capacity} bits<br>
                Used: ${result.used} bits (${((result.used / result.capacity) * 100).toFixed(2)}%)
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
