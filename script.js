// Hybrid Cryptographic System - Complete Implementation
// Hill Cipher + SDES + Steganography

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
            encryptedText,
            keyMatrix,
            binaryBlocks
        };
    }
    
    decrypt(encryptedText, keyMatrix) {
        if (!validateMatrix2x2(keyMatrix, this.ALPHABET_SIZE)) {
            throw new Error('Invalid key matrix: determinant must be coprime with 26');
        }
        
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
        const binaryMessage = this.textToBinary(message) + '1111111111111110'; // 16-bit delimiter
        
        if (binaryMessage.length > originalImageData.data.length / 4) {
            throw new Error('Message too large for image capacity');
        }
        
        let pixelsModified = 0;
        let bitIndex = 0;
        
        // Hide message in LSB of RGB channels
        for (let i = 0; i < modifiedImageData.data.length && bitIndex < binaryMessage.length; i += 4) {
            // Skip alpha channel, only modify RGB
            for (let channel = 0; channel < 3 && bitIndex < binaryMessage.length; channel++) {
                const pixelIndex = i + channel;
                const originalValue = modifiedImageData.data[pixelIndex];
                const messageBit = parseInt(binaryMessage[bitIndex]);
                
                // Clear LSB and set to message bit
                const newValue = (originalValue & 0xFE) | messageBit;
                
                if (newValue !== originalValue) {
                    pixelsModified++;
                }
                
                modifiedImageData.data[pixelIndex] = newValue;
                bitIndex++;
            }
        }
        
        // Put modified image data back to canvas
        this.ctx.putImageData(modifiedImageData, 0, 0);
        const stegoImageData = this.canvasToImageData();
        
        const capacityUsed = (binaryMessage.length / (originalImageData.data.length / 4 * 3)) * 100;
        const psnr = this.calculatePSNR(originalImageData, modifiedImageData);
        
        return {
            originalImageData: imageData,
            stegoImageData,
            hiddenMessage: message,
            pixelsModified,
            capacityUsed,
            psnr
        };
    }
    
    async extractMessage(stegoImageData) {
        const imageData = await this.imageDataToCanvas(stegoImageData);
        let binaryMessage = '';
        const delimiter = '1111111111111110';
        
        // Extract bits from LSB of RGB channels
        for (let i = 0; i < imageData.data.length; i += 4) {
            for (let channel = 0; channel < 3; channel++) {
                const pixelValue = imageData.data[i + channel];
                const lsb = pixelValue & 1;
                binaryMessage += lsb.toString();
                
                // Check for delimiter
                if (binaryMessage.endsWith(delimiter)) {
                    const messageWithoutDelimiter = binaryMessage.slice(0, -delimiter.length);
                    return this.binaryToText(messageWithoutDelimiter);
                }
            }
        }
        
        throw new Error('No hidden message found or message corrupted');
    }
}

// ===== GLOBAL INSTANCES =====
const hillCipher = new HillCipher();
const sdes = new SDES();
const lsbSteganography = new LSBSteganography();

// ===== GLOBAL STATE MANAGEMENT =====
let currentStep = 1;
let currentDecryptStep = 5;
let hillResult = null;
let sdesResult = null;
let steganographyResult = null;
let selectedImage = null;

// Step Configuration
const steps = [
    "Hill Cipher\nEncryption",
    "SDES\nEncryption", 
    "Hide in\nImage",
    "Stego\nImage",
    "Extract\nMessage",
    "SDES\nDecryption",
    "Hill Cipher\nDecryption",
    "Original\nText"
];

const decryptionSteps = [
    {
        number: 5,
        title: "Extract from Image",
        description: "Upload steganographic image to extract hidden message",
        icon: "upload"
    },
    {
        number: 6,
        title: "SDES Decryption", 
        description: "Decrypt 8-bit blocks using SDES algorithm",
        icon: "unlock"
    },
    {
        number: 7,
        title: "Hill Decryption",
        description: "Apply inverse Hill cipher transformation", 
        icon: "key"
    },
    {
        number: 8,
        title: "Original Text",
        description: "Recovered plaintext message",
        icon: "file-text"
    }
];

// Initialize Application
document.addEventListener('DOMContentLoaded', function() {
    initializeStepIndicator();
    initializeMatrixInputs();
    initializeBinaryKeyInputs();
    initializeImageUpload();
    initializeDecryptionSteps();
    updateUI();
});

// Step Indicator Functions
function initializeStepIndicator() {
    const stepIndicator = document.getElementById('stepIndicator');
    
    steps.forEach((step, index) => {
        const stepNumber = index + 1;
        const isActive = stepNumber === currentStep;
        const isCompleted = stepNumber < currentStep;
        
        const stepItem = document.createElement('div');
        stepItem.className = 'step-item';
        
        stepItem.innerHTML = `
            <div class="step-circle ${isCompleted ? 'completed' : isActive ? 'active' : 'pending'}">
                ${stepNumber}
            </div>
            <span class="step-label">${step}</span>
        `;
        
        stepIndicator.appendChild(stepItem);
        
        if (index < steps.length - 1) {
            const connector = document.createElement('div');
            connector.className = `step-connector ${stepNumber < currentStep ? 'completed' : 'pending'}`;
            stepIndicator.appendChild(connector);
        }
    });
    
    updateProgressBar();
}

function updateStepIndicator() {
    const stepItems = document.querySelectorAll('.step-item');
    const connectors = document.querySelectorAll('.step-connector');
    
    stepItems.forEach((item, index) => {
        const stepNumber = index + 1;
        const circle = item.querySelector('.step-circle');
        
        circle.className = 'step-circle ' + 
            (stepNumber < currentStep ? 'completed' : 
             stepNumber === currentStep ? 'active' : 'pending');
    });
    
    connectors.forEach((connector, index) => {
        const stepNumber = index + 1;
        connector.className = `step-connector ${stepNumber < currentStep ? 'completed' : 'pending'}`;
    });
    
    updateProgressBar();
    updateStepDescription();
}

function updateProgressBar() {
    const progressFill = document.getElementById('progressFill');
    const progressPercentage = (currentStep / 8) * 100;
    progressFill.style.width = `${progressPercentage}%`;
}

function updateStepDescription() {
    const stepDescription = document.getElementById('stepDescription');
    stepDescription.textContent = `Step ${currentStep} of 8 - ${steps[currentStep - 1].replace('\n', ' ')}`;
}

// Matrix Input Functions
function initializeMatrixInputs() {
    const matrixInputs = document.querySelectorAll('.matrix-input');
    matrixInputs.forEach(input => {
        input.addEventListener('input', validateMatrix);
    });
    validateMatrix();
}

function getMatrixValues() {
    return [
        [parseInt(document.getElementById('matrix00').value) || 0, parseInt(document.getElementById('matrix01').value) || 0],
        [parseInt(document.getElementById('matrix10').value) || 0, parseInt(document.getElementById('matrix11').value) || 0]
    ];
}

function validateMatrix() {
    const matrix = getMatrixValues();
    const determinant = matrixDeterminant2x2(matrix);
    const modDeterminant = mod(determinant, 26);
    const isValid = validateMatrix2x2(matrix);
    
    document.getElementById('matrixDeterminant').textContent = 
        `Determinant: ${determinant} (mod 26: ${modDeterminant})`;
    
    const validation = document.getElementById('matrixValidation');
    validation.textContent = isValid ? 'Valid' : 'Invalid';
    validation.className = `badge ${isValid ? 'valid' : 'invalid'}`;
    
    const encryptBtn = document.getElementById('hillEncryptBtn');
    const plainText = document.getElementById('plainText').value.trim();
    encryptBtn.disabled = !isValid || !plainText;
}

// Binary Key Input Functions
function initializeBinaryKeyInputs() {
    const bitInputs = document.querySelectorAll('.bit-input');
    bitInputs.forEach(input => {
        input.addEventListener('input', function() {
            if (!/^[01]?$/.test(this.value)) {
                this.value = this.value.slice(-1).replace(/[^01]/, '0');
            }
            validateSDESKey();
        });
    });
}

function getSDESKey() {
    const bitInputs = document.querySelectorAll('.bit-input');
    return Array.from(bitInputs).map(input => input.value || '0').join('');
}

function validateSDESKey() {
    const key = getSDESKey();
    const isValid = key.length === 10 && /^[01]+$/.test(key);
    
    const sdesBtn = document.getElementById('sdesEncryptBtn');
    sdesBtn.disabled = !isValid || !hillResult;
}

// Image Upload Functions
function initializeImageUpload() {
    const fileDropZone = document.getElementById('fileDropZone');
    const imageInput = document.getElementById('imageInput');
    const dropZoneContent = document.getElementById('dropZoneContent');
    
    fileDropZone.addEventListener('click', () => imageInput.click());
    fileDropZone.addEventListener('dragover', handleDragOver);
    fileDropZone.addEventListener('drop', handleDrop);
    imageInput.addEventListener('change', handleFileSelect);
}

function handleDragOver(e) {
    e.preventDefault();
    e.currentTarget.classList.add('dragover');
}

function handleDrop(e) {
    e.preventDefault();
    e.currentTarget.classList.remove('dragover');
    
    const files = Array.from(e.dataTransfer.files);
    if (files.length > 0) {
        handleFile(files[0]);
    }
}

function handleFileSelect(e) {
    const files = e.target.files;
    if (files && files.length > 0) {
        handleFile(files[0]);
    }
}

function handleFile(file) {
    if (!file.type.startsWith('image/')) {
        alert('Please select a valid image file');
        return;
    }

    if (file.size > 10 * 1024 * 1024) { // 10MB limit
        alert('File size must be less than 10MB');
        return;
    }

    selectedImage = file;
    
    const reader = new FileReader();
    reader.onload = function(e) {
        displayImagePreview(e.target.result, file.name);
        updateImageUploadUI();
    };
    reader.readAsDataURL(file);
}

function displayImagePreview(imageSrc, fileName) {
    const dropZoneContent = document.getElementById('dropZoneContent');
    dropZoneContent.innerHTML = `
        <img src="${imageSrc}" alt="Selected cover image" style="max-height: 8rem; border-radius: 0.25rem;">
        <p style="margin-top: 0.5rem; font-size: 0.875rem;">${fileName}</p>
        <span class="badge secondary">Image loaded</span>
    `;
    
    // Update original image preview
    const originalImage = document.getElementById('originalImage');
    originalImage.innerHTML = `<img src="${imageSrc}" alt="Original">`;
}

function updateImageUploadUI() {
    const steganographyBtn = document.getElementById('steganographyBtn');
    steganographyBtn.disabled = !selectedImage || !sdesResult;
}

// Decryption Steps Functions
function initializeDecryptionSteps() {
    const decryptionStepsContainer = document.getElementById('decryptionSteps');
    
    decryptionSteps.forEach(step => {
        const stepElement = document.createElement('div');
        stepElement.className = 'decrypt-step';
        stepElement.id = `decrypt-step-${step.number}`;
        
        stepElement.innerHTML = `
            <div class="decrypt-step-header">
                <div class="decrypt-step-number" id="decrypt-number-${step.number}">${step.number}</div>
                <h4>${step.title}</h4>
            </div>
            <p>${step.description}</p>
            <div class="decrypt-result" id="decrypt-result-${step.number}">
                ${step.number === 8 ? 'Awaiting...' : 
                  step.number === currentDecryptStep ? 
                    `<button class="btn btn-primary" onclick="executeDecryptStep(${step.number})">
                        Step ${step.number}
                    </button>` : 
                  'Awaiting...'}
            </div>
        `;
        
        decryptionStepsContainer.appendChild(stepElement);
    });
}

// Encryption Functions
async function encryptHillCipher() {
    const plainText = document.getElementById('plainText').value.trim();
    const matrix = getMatrixValues();
    
    if (!plainText || !validateMatrix2x2(matrix)) return;
    
    const hillEncryptBtn = document.getElementById('hillEncryptBtn');
    hillEncryptBtn.disabled = true;
    hillEncryptBtn.innerHTML = `
        <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 12a9 9 0 11-6.219-8.56"/>
        </svg>
        Encrypting...
    `;
    
    try {
        hillResult = hillCipher.encrypt(plainText, matrix);
        currentStep = 2;
        
        displayHillResults();
        enableSDESCard();
        updateStepIndicator();
        updateUI();
        
    } catch (error) {
        alert('Hill cipher encryption failed: ' + error.message);
    } finally {
        hillEncryptBtn.disabled = false;
        hillEncryptBtn.innerHTML = `
            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
                <path d="m7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
            Encrypt with Hill Cipher
        `;
    }
}

async function encryptSDES() {
    if (!hillResult) return;
    
    const sdesKey = getSDESKey();
    const sdesEncryptBtn = document.getElementById('sdesEncryptBtn');
    
    sdesEncryptBtn.disabled = true;
    sdesEncryptBtn.innerHTML = `
        <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 12a9 9 0 11-6.219-8.56"/>
        </svg>
        Encrypting...
    `;
    
    try {
        sdesResult = sdes.encrypt(hillResult.encryptedText, sdesKey);
        currentStep = 3;
        
        displaySDESResults();
        enableSteganographyCard();
        updateStepIndicator();
        updateUI();
        
    } catch (error) {
        alert('SDES encryption failed: ' + error.message);
    } finally {
        sdesEncryptBtn.disabled = false;
        sdesEncryptBtn.innerHTML = `
            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
            </svg>
            Encrypt with SDES
        `;
    }
}

async function hideInImage() {
    if (!sdesResult || !selectedImage) return;
    
    const steganographyBtn = document.getElementById('steganographyBtn');
    steganographyBtn.disabled = true;
    steganographyBtn.innerHTML = `
        <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 12a9 9 0 11-6.219-8.56"/>
        </svg>
        Hiding Message...
    `;
    
    try {
        // Get image data URL
        const reader = new FileReader();
        const imageDataURL = await new Promise((resolve) => {
            reader.onload = (e) => resolve(e.target.result);
            reader.readAsDataURL(selectedImage);
        });
        
        // Convert SDES output blocks to string representation
        const messageToHide = sdesResult.output.join('');
        steganographyResult = await lsbSteganography.hideMessage(imageDataURL, messageToHide);
        
        currentStep = 4;
        displaySteganographyResults();
        enableDecryption();
        updateStepIndicator();
        updateUI();
        
    } catch (error) {
        alert('Steganography failed: ' + error.message);
    } finally {
        steganographyBtn.disabled = false;
        steganographyBtn.innerHTML = `
            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/>
                <path d="m2 2 20 20"/>
                <path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/>
            </svg>
            Hide Message in Image
        `;
    }
}

// Display Functions
function displayHillResults() {
    const resultsContent = document.getElementById('resultsContent');
    resultsContent.innerHTML = `
        <div class="result-section fade-in">
            <h4>Original Text</h4>
            <div class="result-content">${hillResult.plainText}</div>
        </div>
        
        <div class="result-section fade-in">
            <h4>Encrypted Text</h4>
            <div class="result-content primary">${hillResult.encryptedText}</div>
        </div>
        
        <div class="result-section fade-in">
            <h4>Binary Representation (8-bit blocks)</h4>
            <div class="result-content accent scrollable">${hillResult.binaryBlocks.join(' ')}</div>
        </div>
        
        <div class="result-section fade-in">
            <h4>Key Matrix Used</h4>
            <div class="result-content">
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.5rem; width: fit-content;">
                    ${hillResult.keyMatrix.flat().map(value => 
                        `<span class="badge secondary" style="text-align: center;">${value}</span>`
                    ).join('')}
                </div>
            </div>
        </div>
    `;
}

function displaySDESResults() {
    const resultsContent = document.getElementById('resultsContent');
    resultsContent.innerHTML += `
        <div class="result-section fade-in">
            <h4>Hill Cipher Input (8-bit blocks)</h4>
            <div class="result-content primary">${sdesResult.input.join(' ')}</div>
        </div>
        
        <div class="result-section fade-in">
            <h4>SDES Encrypted Output</h4>
            <div class="result-content secondary">${sdesResult.output.join(' ')}</div>
        </div>
        
        <div class="result-section fade-in">
            <h4>Key Schedule</h4>
            <div class="result-content">
                <div style="font-size: 0.875rem; line-height: 1.4;">
                    <div>K1: <code class="result-content accent" style="display: inline; padding: 0.25rem;">${sdesResult.subKeys.k1}</code></div>
                    <div>K2: <code class="result-content accent" style="display: inline; padding: 0.25rem;">${sdesResult.subKeys.k2}</code></div>
                </div>
            </div>
        </div>
    `;
}

function displaySteganographyResults() {
    // Update stego image
    const stegoImage = document.getElementById('stegoImage');
    stegoImage.innerHTML = `<img src="${steganographyResult.stegoImageData}" alt="Steganographic">`;
    
    // Update statistics
    const stats = document.querySelectorAll('.stat-value');
    stats[0].textContent = steganographyResult.pixelsModified;
    stats[1].textContent = steganographyResult.capacityUsed.toFixed(1) + '%';
    stats[2].textContent = steganographyResult.psnr.toFixed(1);
}

// UI State Functions
function enableSDESCard() {
    const sdesCard = document.getElementById('sdesCard');
    sdesCard.classList.remove('disabled');
    
    const stepNumber = sdesCard.querySelector('.step-number');
    stepNumber.classList.remove('disabled');
    
    validateSDESKey();
}

function enableSteganographyCard() {
    const steganographyCard = document.getElementById('steganographyCard');
    steganographyCard.classList.remove('disabled');
    
    const stepNumber = steganographyCard.querySelector('.step-number');
    stepNumber.classList.remove('disabled');
    
    updateImageUploadUI();
}

function enableDecryption() {
    const startDecryptionBtn = document.getElementById('startDecryptionBtn');
    startDecryptionBtn.disabled = false;
}

function updateUI() {
    // Update plain text input listener
    const plainText = document.getElementById('plainText');
    plainText.addEventListener('input', validateMatrix);
}

// Decryption Functions
async function startDecryption() {
    if (!steganographyResult) return;
    
    currentDecryptStep = 5;
    await executeDecryptStep(5);
}

async function executeDecryptStep(stepNumber) {
    const stepElement = document.getElementById(`decrypt-step-${stepNumber}`);
    const numberElement = document.getElementById(`decrypt-number-${stepNumber}`);
    const resultElement = document.getElementById(`decrypt-result-${stepNumber}`);
    
    // Mark as active
    numberElement.classList.add('active');
    resultElement.innerHTML = `
        <button class="btn btn-primary" disabled>
            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 12a9 9 0 11-6.219-8.56"/>
            </svg>
            Processing...
        </button>
    `;
    
    try {
        let result = '';
        
        switch (stepNumber) {
            case 5: // Extract from image
                result = await lsbSteganography.extractMessage(steganographyResult.stegoImageData);
                displayDecryptionResult(5, result, 'Extracted Binary Message');
                setTimeout(() => executeDecryptStep(6), 500);
                break;
                
            case 6: // SDES Decryption
                const extractedMessage = await lsbSteganography.extractMessage(steganographyResult.stegoImageData);
                const blocks = extractedMessage.match(/.{1,8}/g) || [];
                result = sdes.decrypt(blocks, sdesResult.key);
                displayDecryptionResult(6, result, 'After SDES Decryption');
                setTimeout(() => executeDecryptStep(7), 500);
                break;
                
            case 7: // Hill Decryption
                const extractedMsg = await lsbSteganography.extractMessage(steganographyResult.stegoImageData);
                const sdesBlocks = extractedMsg.match(/.{1,8}/g) || [];
                const sdesDecrypted = sdes.decrypt(sdesBlocks, sdesResult.key);
                result = hillCipher.decrypt(sdesDecrypted, hillResult.keyMatrix);
                displayDecryptionResult(7, result, 'After Hill Decryption');
                setTimeout(() => executeDecryptStep(8), 500);
                break;
                
            case 8: // Final result
                const finalExtracted = await lsbSteganography.extractMessage(steganographyResult.stegoImageData);
                const finalSdesBlocks = finalExtracted.match(/.{1,8}/g) || [];
                const finalSdesDecrypted = sdes.decrypt(finalSdesBlocks, sdesResult.key);
                result = hillCipher.decrypt(finalSdesDecrypted, hillResult.keyMatrix);
                displayFinalResult(result);
                break;
        }
        
        // Mark as completed
        numberElement.classList.remove('active');
        numberElement.classList.add('completed');
        
        currentDecryptStep = stepNumber + 1;
        
    } catch (error) {
        alert(`Decryption step ${stepNumber} failed: ` + error.message);
        resultElement.innerHTML = `
            <div class="decrypt-result" style="background-color: hsl(var(--error) / 0.2); color: hsl(var(--error));">
                Error: ${error.message}
            </div>
        `;
    }
}

function displayDecryptionResult(stepNumber, result, title) {
    const resultElement = document.getElementById(`decrypt-result-${stepNumber}`);
    resultElement.innerHTML = `
        <div class="decrypt-result completed">
            Data Ready
        </div>
    `;
    
    // Add to decryption results section
    const decryptionResults = document.getElementById('decryptionResults');
    if (!decryptionResults.style.display || decryptionResults.style.display === 'none') {
        decryptionResults.style.display = 'block';
        decryptionResults.innerHTML = '<h4>Decryption Results</h4>';
    }
    
    const resultDiv = document.createElement('div');
    resultDiv.className = 'result-section fade-in';
    resultDiv.innerHTML = `
        <h4 style="font-size: 0.875rem;">${title}</h4>
        <div class="result-content scrollable" style="max-height: 5rem; font-size: 0.875rem;">
            ${stepNumber === 5 ? result.slice(0, 200) + (result.length > 200 ? '...' : '') : result}
        </div>
    `;
    
    decryptionResults.appendChild(resultDiv);
}

function displayFinalResult(result) {
    const resultElement = document.getElementById(`decrypt-result-8`);
    resultElement.innerHTML = `
        <div class="final-result">
            <h4>Final Plaintext</h4>
            <p>${result}</p>
        </div>
    `;
    
    // Update step indicator to show completion
    currentStep = 8;
    updateStepIndicator();
}

// Export Function
function exportResults() {
    const results = {
        timestamp: new Date().toISOString(),
        hillCipher: hillResult,
        sdes: sdesResult,
        steganography: steganographyResult ? {
            pixelsModified: steganographyResult.pixelsModified,
            capacityUsed: steganographyResult.capacityUsed,
            psnr: steganographyResult.psnr
        } : null
    };
    
    const dataStr = JSON.stringify(results, null, 2);
    const dataBlob = new Blob([dataStr], {type: 'application/json'});
    
    const link = document.createElement('a');
    link.href = URL.createObjectURL(dataBlob);
    link.download = `hybrid-crypto-results-${Date.now()}.json`;
    link.click();
}
