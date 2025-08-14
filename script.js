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
        'Hill Cipher',
        'SDES Encryption', 
        'Steganography',
        'Complete'
    ];
    
    steps.forEach((step, index) => {
        const stepElement = document.createElement('div');
        stepElement.className = `step-item ${index === 0 ? 'active' : ''}`;
        stepElement.innerHTML = `
            <div class="step-number">${index + 1}</div>
            <div class="step-label">${step}</div>
            <div class="step-status">${index === 0 ? 'Active' : 'Pending'}</div>
        `;
        stepIndicator.appendChild(stepElement);
    });
}

function setupEventListeners() {
    // Matrix input validation
    const matrixInputs = document.querySelectorAll('.matrix-input');
    matrixInputs.forEach(input => {
        input.addEventListener('input', validateMatrix);
    });
    
    // Binary key validation
    const bitInputs = document.querySelectorAll('.bit-input');
    bitInputs.forEach((input, index) => {
        input.addEventListener('input', (e) => {
            const value = e.target.value;
            if (value !== '0' && value !== '1') {
                e.target.value = '';
            }
            validateBinaryKey();
        });
    });
    
    // File upload handlers
    setupFileUploads();
}

function setupFileUploads() {
    // Main steganography file upload
    const fileDropZone = document.getElementById('fileDropZone');
    const fileInput = document.getElementById('imageInput');
    const dropZoneContent = document.getElementById('dropZoneContent');
    
    // Decrypt file upload
    const decryptDropZone = document.getElementById('decryptDropZone');
    const decryptFileInput = document.getElementById('decryptImageInput');
    const decryptDropContent = document.getElementById('decryptDropContent');
    
    // Setup drag and drop for main upload
    setupDropZone(fileDropZone, fileInput, dropZoneContent, handleImageUpload);
    
    // Setup drag and drop for decrypt upload
    setupDropZone(decryptDropZone, decryptFileInput, decryptDropContent, handleDecryptImageUpload);
    
    // File input change handlers
    fileInput.addEventListener('change', handleImageUpload);
    decryptFileInput.addEventListener('change', handleDecryptImageUpload);
    
    // Click handlers for choose file buttons
    fileDropZone.addEventListener('click', () => fileInput.click());
    decryptDropZone.addEventListener('click', () => decryptFileInput.click());
}

function setupDropZone(dropZone, fileInput, dropContent, handler) {
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });
    
    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });
    
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            fileInput.files = files;
            handler();
        }
    });
}

function handleImageUpload() {
    const fileInput = document.getElementById('imageInput');
    const file = fileInput.files[0];
    
    if (!file) return;
    
    if (!file.type.startsWith('image/')) {
        alert('Please select a valid image file');
        return;
    }
    
    if (file.size > 10 * 1024 * 1024) {
        alert('Image file too large. Maximum size is 10MB');
        return;
    }
    
    const reader = new FileReader();
    reader.onload = function(e) {
        originalImageData = e.target.result;
        
        // Update drop zone to show selected image
        const dropZoneContent = document.getElementById('dropZoneContent');
        dropZoneContent.innerHTML = `
            <img src="${originalImageData}" alt="Selected Image" style="max-width: 150px; max-height: 150px; border-radius: 8px;">
            <p>Image selected: ${file.name}</p>
            <small>Click to change image</small>
        `;
        
        // Enable steganography step if SDES is complete
        if (sdesResult) {
            enableSteganography();
        }
    };
    reader.readAsDataURL(file);
}

function handleDecryptImageUpload() {
    const fileInput = document.getElementById('decryptImageInput');
    const file = fileInput.files[0];
    
    if (!file) return;
    
    if (!file.type.startsWith('image/')) {
        alert('Please select a valid image file');
        return;
    }
    
    const reader = new FileReader();
    reader.onload = function(e) {
        const decryptImageData = e.target.result;
        
        // Update drop zone to show selected image
        const dropContent = document.getElementById('decryptDropContent');
        dropContent.innerHTML = `
            <img src="${decryptImageData}" alt="Decrypt Image" style="max-width: 150px; max-height: 150px; border-radius: 8px;">
            <p>Stego image: ${file.name}</p>
            <small>Click to change image</small>
        `;
        
        // Enable decrypt button
        document.getElementById('decryptBtn').disabled = false;
        
        // Store for decryption
        window.decryptImageData = decryptImageData;
    };
    reader.readAsDataURL(file);
}

function validateMatrix() {
    const matrix = getMatrixFromInputs();
    const determinant = matrixDeterminant2x2(matrix);
    const isValid = validateMatrix2x2(matrix);
    
    // Update display
    document.getElementById('matrixDeterminant').textContent = 
        `Determinant: ${determinant} (mod 26: ${mod(determinant, 26)})`;
    
    const validationBadge = document.getElementById('matrixValidation');
    if (isValid) {
        validationBadge.textContent = 'Valid';
        validationBadge.className = 'badge valid animated-badge';
    } else {
        validationBadge.textContent = 'Invalid';
        validationBadge.className = 'badge invalid animated-badge';
    }
    
    return isValid;
}

function validateBinaryKey() {
    const key = getBinaryKeyFromInputs();
    const isValid = key.length === 10 && /^[01]{10}$/.test(key);
    
    // Update validation display if needed
    return isValid;
}

function getMatrixFromInputs() {
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

function getBinaryKeyFromInputs() {
    const bitInputs = document.querySelectorAll('.bit-input');
    let key = '';
    bitInputs.forEach(input => {
        key += input.value || '0';
    });
    return key;
}

function updateStepIndicator() {
    const stepItems = document.querySelectorAll('.step-item');
    const progressFill = document.getElementById('progressFill');
    const stepDescription = document.getElementById('stepDescription');
    
    const descriptions = [
        'Step 1 of 4 - Hill Cipher Encryption',
        'Step 2 of 4 - SDES Encryption',
        'Step 3 of 4 - Image Steganography',
        'Step 4 of 4 - Process Complete'
    ];
    
    stepItems.forEach((item, index) => {
        item.classList.remove('active', 'completed');
        const status = item.querySelector('.step-status');
        
        if (index < currentStep - 1) {
            item.classList.add('completed');
            status.textContent = 'Completed';
        } else if (index === currentStep - 1) {
            item.classList.add('active');
            status.textContent = 'Active';
        } else {
            status.textContent = 'Pending';
        }
    });
    
    // Update progress bar
    const progress = ((currentStep - 1) / 3) * 100;
    progressFill.style.width = `${progress}%`;
    
    // Update description
    stepDescription.textContent = descriptions[currentStep - 1] || descriptions[3];
}

function updateProcessFlow(step, status) {
    const flowSteps = ['flowStep1', 'flowStep2', 'flowStep3'];
    const stepElement = document.getElementById(flowSteps[step - 1]);
    
    if (stepElement) {
        const statusElement = stepElement.querySelector('.flow-status');
        statusElement.textContent = status;
        
        stepElement.classList.remove('active', 'completed');
        if (status === 'Active') {
            stepElement.classList.add('active');
        } else if (status === 'Completed') {
            stepElement.classList.add('completed');
        }
    }
}

// ===== ENCRYPTION FUNCTIONS =====

function encryptHillCipher() {
    const plainText = document.getElementById('plainText').value.trim();
    
    if (!plainText) {
        alert('Please enter a message to encrypt');
        return;
    }
    
    if (!validateMatrix()) {
        alert('Invalid matrix. Please check your key matrix values');
        return;
    }
    
    try {
        const matrix = getMatrixFromInputs();
        const hillCipher = new HillCipher();
        hillCipherResult = hillCipher.encrypt(plainText, matrix);
        
        console.log('Hill Cipher Result:', hillCipherResult);
        
        // Update UI
        displayHillResult();
        updateProcessFlow(1, 'Completed');
        enableSDES();
        currentStep = 2;
        updateStepIndicator();
        
    } catch (error) {
        console.error('Hill Cipher Error:', error);
        alert('Hill Cipher encryption failed: ' + error.message);
    }
}

function encryptSDES() {
    if (!hillCipherResult) {
        alert('Please complete Hill Cipher encryption first');
        return;
    }
    
    const binaryKey = getBinaryKeyFromInputs();
    
    if (!validateBinaryKey()) {
        alert('Invalid SDES key. Please enter exactly 10 binary digits (0 or 1)');
        return;
    }
    
    try {
        const sdes = new SDES();
        sdesResult = sdes.encrypt(hillCipherResult.encryptedText, binaryKey);
        
        console.log('SDES Result:', sdesResult);
        
        // Update UI
        displaySDESResult();
        updateProcessFlow(2, 'Completed');
        
        // Enable steganography if image is uploaded
        if (originalImageData) {
            enableSteganography();
        }
        
        currentStep = 3;
        updateStepIndicator();
        
    } catch (error) {
        console.error('SDES Error:', error);
        alert('SDES encryption failed: ' + error.message);
    }
}

function hideInImage() {
    if (!sdesResult) {
        alert('Please complete SDES encryption first');
        return;
    }
    
    if (!originalImageData) {
        alert('Please select an image file first');
        return;
    }
    
    try {
        const steganography = new LSBSteganography();
        const messageBinary = sdesResult.output.join('');
        
        steganography.hideMessage(originalImageData, messageBinary).then(result => {
            steganographyResult = result;
            
            console.log('Steganography Result:', steganographyResult);
            
            // Update UI
            displaySteganographyResult();
            updateProcessFlow(3, 'Completed');
            currentStep = 4;
            updateStepIndicator();
            
            // Show completion message
            showCompletionMessage();
            
        }).catch(error => {
            console.error('Steganography Error:', error);
            alert('Steganography failed: ' + error.message);
        });
        
    } catch (error) {
        console.error('Steganography Error:', error);
        alert('Steganography failed: ' + error.message);
    }
}

// ===== UI UPDATE FUNCTIONS =====

function displayHillResult() {
    const hillResult = document.getElementById('hillResult');
    document.getElementById('hillOriginal').textContent = hillCipherResult.originalText;
    document.getElementById('hillEncrypted').textContent = hillCipherResult.encryptedText;
    document.getElementById('hillBinary').textContent = hillCipherResult.binaryBlocks.join(' ');
    
    hillResult.style.display = 'block';
    document.getElementById('placeholderMessage').style.display = 'none';
}

function displaySDESResult() {
    const sdesResult_elem = document.getElementById('sdesResult');
    document.getElementById('sdesInput').textContent = sdesResult.input.join(' ');
    document.getElementById('sdesOutput').textContent = sdesResult.output.join(' ');
    document.getElementById('sdesKeyUsed').textContent = sdesResult.key;
    
    sdesResult_elem.style.display = 'block';
}

function displaySteganographyResult() {
    const stegoResult = document.getElementById('stegoResult');
    document.getElementById('stegoMessage').textContent = steganographyResult.messageBinary;
    document.getElementById('stegoSize').textContent = 
        `${steganographyResult.imageSize.width} × ${steganographyResult.imageSize.height}`;
    document.getElementById('stegoCapacity').textContent = 
        `${steganographyResult.used} / ${steganographyResult.capacity} bits (${(steganographyResult.used / steganographyResult.capacity * 100).toFixed(2)}%)`;
    document.getElementById('stegoPSNR').textContent = steganographyResult.psnr.toFixed(2);
    
    // Show image comparison
    const imageComparison = document.getElementById('imageComparison');
    document.getElementById('originalImg').src = steganographyResult.originalImage;
    document.getElementById('stegoImg').src = steganographyResult.stegoImage;
    imageComparison.style.display = 'block';
    
    stegoResult.style.display = 'block';
}

function enableSDES() {
    const sdesCard = document.getElementById('sdesCard');
    const sdesBtn = document.getElementById('sdesEncryptBtn');
    
    sdesCard.classList.remove('disabled');
    sdesBtn.disabled = false;
    
    document.querySelector('#sdesCard .step-number').classList.remove('disabled');
}

function enableSteganography() {
    const stegoCard = document.getElementById('steganographyCard');
    const stegoBtn = document.getElementById('steganographyBtn');
    
    stegoCard.classList.remove('disabled');
    stegoBtn.disabled = false;
    
    document.querySelector('#steganographyCard .step-number').classList.remove('disabled');
}

function showCompletionMessage() {
    // Could add a success animation or modal here
    alert('Hybrid encryption process completed successfully! You can now decrypt the stego image.');
}

// ===== DECRYPTION FUNCTIONS =====

function startFullDecryption() {
    if (!window.decryptImageData) {
        alert('Please select a stego image for decryption');
        return;
    }
    
    if (!hillCipherResult || !sdesResult) {
        alert('Original encryption data not available. Please complete encryption first or provide the necessary keys.');
        return;
    }
    
    try {
        const steganography = new LSBSteganography();
        
        steganography.extractMessage(window.decryptImageData).then(extractedBinary => {
            console.log('Extracted binary:', extractedBinary);
            
            // Convert binary string to blocks for SDES decryption
            const binaryBlocks = [];
            for (let i = 0; i < extractedBinary.length; i += 8) {
                binaryBlocks.push(extractedBinary.slice(i, i + 8).padEnd(8, '0'));
            }
            
            console.log('Binary blocks for SDES:', binaryBlocks);
            
            // Decrypt with SDES
            const sdes = new SDES();
            const sdesDecrypted = sdes.decrypt(binaryBlocks, sdesResult.key);
            
            console.log('SDES decrypted:', sdesDecrypted);
            
            // Decrypt with Hill Cipher
            const hillCipher = new HillCipher();
            const finalDecrypted = hillCipher.decrypt(sdesDecrypted, hillCipherResult.keyMatrix, hillCipherResult.originalLength);
            
            console.log('Final decrypted:', finalDecrypted);
            
            // Display results
            displayDecryptionResult(extractedBinary, sdesDecrypted, finalDecrypted);
            
        }).catch(error => {
            console.error('Decryption Error:', error);
            alert('Decryption failed: ' + error.message);
        });
        
    } catch (error) {
        console.error('Decryption Error:', error);
        alert('Decryption failed: ' + error.message);
    }
}

function displayDecryptionResult(extractedBinary, sdesDecrypted, finalMessage) {
    const decryptResult = document.getElementById('decryptResult');
    const decryptedMessage = document.getElementById('decryptedMessage');
    const extractedBinaryElem = document.getElementById('extractedBinary');
    const sdesDecryptedElem = document.getElementById('sdesDecrypted');
    const hillDecryptedElem = document.getElementById('hillDecrypted');
    
    decryptedMessage.textContent = finalMessage;
    extractedBinaryElem.textContent = extractedBinary.substring(0, 50) + (extractedBinary.length > 50 ? '...' : '');
    sdesDecryptedElem.textContent = sdesDecrypted;
    hillDecryptedElem.textContent = finalMessage;
    
    decryptResult.style.display = 'block';
}

// ===== UTILITY FUNCTIONS =====

function exportResults() {
    if (!hillCipherResult && !sdesResult && !steganographyResult) {
        alert('No results to export. Please complete at least one encryption step.');
        return;
    }
    
    const results = {
        timestamp: new Date().toISOString(),
        hillCipher: hillCipherResult,
        sdes: sdesResult,
        steganography: steganographyResult ? {
            ...steganographyResult,
            originalImage: null, // Don't export large image data
            stegoImage: null
        } : null
    };
    
    const dataStr = JSON.stringify(results, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    
    const link = document.createElement('a');
    link.href = URL.createObjectURL(dataBlob);
    link.download = 'hybrid-crypto-results.json';
    link.click();
    
    URL.revokeObjectURL(link.href);
}

// ===== ERROR HANDLING =====

window.addEventListener('error', function(e) {
    console.error('Global Error:', e.error);
    alert('An unexpected error occurred. Please check the console for details.');
});

window.addEventListener('unhandledrejection', function(e) {
    console.error('Unhandled Promise Rejection:', e.reason);
    alert('An async operation failed. Please check the console for details.');
});
