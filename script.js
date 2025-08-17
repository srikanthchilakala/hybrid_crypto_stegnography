// Global variables to store workflow data
let workflowData = {
    plainText: "",
    originalTextLength: 0,
    hillKey: [[3, 2], [5, 7]],
    hillEncrypted: "",
    hillBits: "",
    sdesKey: "1010000010",
    sdesEncrypted: "",
    coverImage: null,
    stegoImage: null,
    extractedBits: "",
    sdesDecrypted: "",
    hillDecrypted: "",
    finalResult: ""
};

let currentStep = 1;

// Hill Cipher Implementation
class HillCipher {
    static originalTextLength = 0;

    static setOriginalLength(length) {
        this.originalTextLength = length;
    }

    static textToNumbers(text) {
        return text.toUpperCase().split('').map(char => char.charCodeAt(0) - 65);
    }

    static numbersToText(numbers) {
        return numbers.map(num => String.fromCharCode((num % 26) + 65)).join('');
    }

    static addPadding(text) {
        let padded = text.toUpperCase();
        while (padded.length % 2 !== 0) {
            padded += 'X';
        }
        return padded;
    }

    static encrypt(text, keyMatrix) {
        this.setOriginalLength(text.length);
        const paddedText = this.addPadding(text);
        const numbers = this.textToNumbers(paddedText);
        const encrypted = [];

        for (let i = 0; i < numbers.length; i += 2) {
            const vector = [numbers[i], numbers[i + 1]];
            const result = [
                (keyMatrix[0][0] * vector[0] + keyMatrix[0][1] * vector[1]) % 26,
                (keyMatrix[1][0] * vector[0] + keyMatrix[1][1] * vector[1]) % 26
            ];
            encrypted.push(...result);
        }

        return this.numbersToText(encrypted);
    }

    static modInverse(a, m) {
        for (let i = 1; i < m; i++) {
            if ((a * i) % m === 1) {
                return i;
            }
        }
        throw new Error('Modular inverse does not exist');
    }

    static determinant(matrix) {
        return (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % 26;
    }

    static inverseMatrix(keyMatrix) {
        const det = this.determinant(keyMatrix);
        if (det === 0) {
            throw new Error('Matrix is not invertible');
        }

        const detInv = this.modInverse((det + 26) % 26, 26);
        
        return [
            [(keyMatrix[1][1] * detInv) % 26, (-keyMatrix[0][1] * detInv + 26 * 26) % 26],
            [(-keyMatrix[1][0] * detInv + 26 * 26) % 26, (keyMatrix[0][0] * detInv) % 26]
        ];
    }

    static decrypt(ciphertext, keyMatrix) {
        const inverseKey = this.inverseMatrix(keyMatrix);
        const decrypted = this.encrypt(ciphertext, inverseKey);
        
        // Remove trailing X padding that was added during encryption
        let result = decrypted;
        
        // Remove trailing X's that were added as padding
        while (result.endsWith('X') && result.length > 1) {
            result = result.slice(0, -1);
        }
        
        // Also use stored original length if available for more precision
        if (this.originalTextLength > 0 && this.originalTextLength < result.length) {
            result = result.substring(0, this.originalTextLength);
        }
        
        return result;
    }

    static textToBinary(text) {
        return text.split('').map(char => 
            char.charCodeAt(0).toString(2).padStart(8, '0')
        ).join('');
    }

    static binaryToText(binary) {
        const result = [];
        for (let i = 0; i < binary.length; i += 8) {
            const byte = binary.substr(i, 8);
            if (byte.length === 8) {
                result.push(String.fromCharCode(parseInt(byte, 2)));
            }
        }
        return result.join('');
    }
}

// SDES Implementation
class SDES {
    static P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6];
    static P8 = [6, 3, 7, 4, 8, 5, 10, 9];
    static IP = [2, 6, 3, 1, 4, 8, 5, 7];
    static EP = [4, 1, 2, 3, 2, 3, 4, 1];
    static P4 = [2, 4, 3, 1];
    static IP_INV = [4, 1, 3, 5, 7, 2, 8, 6];

    static S0 = [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 3, 2]
    ];

    static S1 = [
        [0, 1, 2, 3],
        [2, 0, 1, 3],
        [3, 0, 1, 0],
        [2, 1, 0, 3]
    ];

    static permute(input, permutationTable) {
        return permutationTable.map(pos => input[pos - 1]).join('');
    }

    static leftShift(bits, positions) {
        return bits.slice(positions) + bits.slice(0, positions);
    }

    static xor(a, b) {
        return a.split('').map((bit, i) => 
            (parseInt(bit) ^ parseInt(b[i])).toString()
        ).join('');
    }

    static sBox(input, sbox) {
        const row = parseInt(input[0] + input[3], 2);
        const col = parseInt(input[1] + input[2], 2);
        return sbox[row][col].toString(2).padStart(2, '0');
    }

    static generateKeys(key) {
        const p10 = this.permute(key, this.P10);
        const left1 = this.leftShift(p10.slice(0, 5), 1);
        const right1 = this.leftShift(p10.slice(5), 1);
        const k1 = this.permute(left1 + right1, this.P8);

        const left2 = this.leftShift(left1, 2);
        const right2 = this.leftShift(right1, 2);
        const k2 = this.permute(left2 + right2, this.P8);

        return [k1, k2];
    }

    static f(right, key) {
        const expanded = this.permute(right, this.EP);
        const xored = this.xor(expanded, key);
        
        const left = xored.slice(0, 4);
        const rightPart = xored.slice(4);
        
        const s0Result = this.sBox(left, this.S0);
        const s1Result = this.sBox(rightPart, this.S1);
        
        return this.permute(s0Result + s1Result, this.P4);
    }

    static encryptBlock(plaintext, keys) {
        let current = this.permute(plaintext, this.IP);
        let left = current.slice(0, 4);
        let right = current.slice(4);

        // Round 1
        const fResult1 = this.f(right, keys[0]);
        const newLeft = right;
        const newRight = this.xor(left, fResult1);

        // Round 2
        const fResult2 = this.f(newRight, keys[1]);
        const finalLeft = this.xor(newLeft, fResult2);
        const finalRight = newRight;

        return this.permute(finalLeft + finalRight, this.IP_INV);
    }

    static encrypt(plaintext, key) {
        const keys = this.generateKeys(key);
        let result = '';
        
        for (let i = 0; i < plaintext.length; i += 8) {
            const block = plaintext.slice(i, i + 8);
            if (block.length === 8) {
                result += this.encryptBlock(block, keys);
            }
        }
        
        return result;
    }

    static decrypt(ciphertext, key) {
        const keys = this.generateKeys(key);
        // For decryption, use keys in reverse order
        const reverseKeys = [keys[1], keys[0]];
        let result = '';
        
        for (let i = 0; i < ciphertext.length; i += 8) {
            const block = ciphertext.slice(i, i + 8);
            if (block.length === 8) {
                result += this.encryptBlock(block, reverseKeys);
            }
        }
        
        return result;
    }
}

// Steganography Implementation
class Steganography {
    static hideMessage(imageData, message) {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        
        canvas.width = imageData.width;
        canvas.height = imageData.height;
        
        const data = new Uint8ClampedArray(imageData.data);
        const messageBits = message + '1111111111111110'; // End marker
        
        for (let i = 0; i < messageBits.length && i < data.length; i++) {
            data[i * 4] = (data[i * 4] & 0xFE) | parseInt(messageBits[i]);
        }
        
        const newImageData = new ImageData(data, canvas.width, canvas.height);
        ctx.putImageData(newImageData, 0, 0);
        
        return canvas.toDataURL();
    }

    static extractMessage(imageData) {
        const data = imageData.data;
        let message = '';
        const endMarker = '1111111111111110';
        
        for (let i = 0; i < data.length; i += 4) {
            const bit = (data[i] & 1).toString();
            message += bit;
            
            if (message.endsWith(endMarker)) {
                return message.slice(0, -endMarker.length);
            }
        }
        
        return message;
    }
}

// UI Functions
function updateStepStatus(stepNumber, status) {
    const stepCard = document.getElementById(`step${stepNumber}`);
    const stepElement = stepCard.querySelector('.step-number');
    
    stepCard.classList.remove('active', 'completed');
    
    if (status === 'active') {
        stepCard.classList.add('active');
        stepCard.classList.add('processing');
    } else if (status === 'completed') {
        stepCard.classList.add('completed');
        stepCard.classList.remove('processing');
    }
}

function showResult(stepId, title, content) {
    const resultDiv = document.getElementById(stepId);
    resultDiv.innerHTML = `<h4>${title}</h4><p>${content}</p>`;
    resultDiv.classList.add('show');
}

function loadImageToCanvas(file, canvasId) {
    return new Promise((resolve) => {
        const canvas = document.getElementById(canvasId);
        const ctx = canvas.getContext('2d');
        const img = new Image();
        
        img.onload = function() {
            canvas.width = img.width;
            canvas.height = img.height;
            ctx.drawImage(img, 0, 0);
            
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            resolve(imageData);
        };
        
        img.src = URL.createObjectURL(file);
    });
}

function displayImageOnCanvas(dataUrl, canvasId) {
    const canvas = document.getElementById(canvasId);
    const ctx = canvas.getContext('2d');
    const img = new Image();
    
    img.onload = function() {
        canvas.width = img.width;
        canvas.height = img.height;
        ctx.drawImage(img, 0, 0);
    };
    
    img.src = dataUrl;
}

async function startEncryption() {
    const plaintext = document.getElementById('plaintext').value;
    const imageFile = document.getElementById('imageInput').files[0];
    
    if (!plaintext || !imageFile) {
        alert('Please enter text and select an image');
        return;
    }
    
    workflowData.plainText = plaintext.toUpperCase();
    workflowData.originalTextLength = plaintext.length;
    workflowData.coverImage = imageFile;
    
    // Update key matrix from inputs
    workflowData.hillKey = [
        [parseInt(document.getElementById('key00').value), parseInt(document.getElementById('key01').value)],
        [parseInt(document.getElementById('key10').value), parseInt(document.getElementById('key11').value)]
    ];
    
    workflowData.sdesKey = document.getElementById('sdesKey').value;
    
    currentStep = 2;
    
    // Step 2: Hill Cipher Encryption
    updateStepStatus(2, 'active');
    
    setTimeout(() => {
        try {
            HillCipher.setOriginalLength(workflowData.originalTextLength);
            workflowData.hillEncrypted = HillCipher.encrypt(workflowData.plainText, workflowData.hillKey);
            workflowData.hillBits = HillCipher.textToBinary(workflowData.hillEncrypted);
            
            showResult('hillResult', 'Hill Cipher Result:', 
                `Encrypted: ${workflowData.hillEncrypted}<br>Binary: ${workflowData.hillBits}`);
            
            updateStepStatus(2, 'completed');
            currentStep = 3;
            
            // Step 3: SDES Encryption
            setTimeout(() => {
                updateStepStatus(3, 'active');
                
                workflowData.sdesEncrypted = SDES.encrypt(workflowData.hillBits, workflowData.sdesKey);
                
                showResult('sdesResult', 'SDES Result:', 
                    `Encrypted Binary: ${workflowData.sdesEncrypted}`);
                
                updateStepStatus(3, 'completed');
                currentStep = 4;
                
                // Step 4: Steganography
                setTimeout(async () => {
                    updateStepStatus(4, 'active');
                    
                    const imageData = await loadImageToCanvas(workflowData.coverImage, 'originalCanvas');
                    workflowData.stegoImage = Steganography.hideMessage(imageData, workflowData.sdesEncrypted);
                    
                    displayImageOnCanvas(workflowData.stegoImage, 'stegoCanvas');
                    
                    showResult('stegoResult', 'Steganography Complete:', 
                        'Message hidden in image successfully! Image auto-uploaded for decryption.');
                    
                    updateStepStatus(4, 'completed');
                    currentStep = 5;
                    
                }, 1000);
            }, 1000);
        } catch (error) {
            alert('Encryption failed: ' + error.message);
        }
    }, 500);
}

async function startDecryption() {
    if (!workflowData.stegoImage) {
        alert('No encrypted image available. Please complete encryption first.');
        return;
    }
    
    currentStep = 5;
    
    // Step 5: Extract from Steganography
    updateStepStatus(5, 'active');
    
    setTimeout(() => {
        const canvas = document.getElementById('stegoCanvas');
        const ctx = canvas.getContext('2d');
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        
        workflowData.extractedBits = Steganography.extractMessage(imageData);
        
        showResult('extractResult', 'Extraction Complete:', 
            `Extracted Binary: ${workflowData.extractedBits}`);
        
        updateStepStatus(5, 'completed');
        currentStep = 6;
        
        // Step 6: SDES Decryption
        setTimeout(() => {
            updateStepStatus(6, 'active');
            
            workflowData.sdesDecrypted = SDES.decrypt(workflowData.extractedBits, workflowData.sdesKey);
            
            showResult('sdesDecryptResult', 'SDES Decryption Complete:', 
                `Decrypted Binary: ${workflowData.sdesDecrypted}`);
            
            updateStepStatus(6, 'completed');
            currentStep = 7;
            
            // Step 7: Hill Cipher Decryption
            setTimeout(() => {
                updateStepStatus(7, 'active');
                
                HillCipher.setOriginalLength(workflowData.originalTextLength);
                const textFromBinary = HillCipher.binaryToText(workflowData.sdesDecrypted);
                workflowData.hillDecrypted = textFromBinary;
                workflowData.finalResult = HillCipher.decrypt(textFromBinary, workflowData.hillKey);
                
                showResult('hillDecryptResult', 'Hill Cipher Decryption Complete:', 
                    `Decrypted Text: ${workflowData.hillDecrypted}<br>Final Result: ${workflowData.finalResult}`);
                
                updateStepStatus(7, 'completed');
                currentStep = 8;
                
                // Step 8: Final Result
                setTimeout(() => {
                    updateStepStatus(8, 'active');
                    
                    document.getElementById('finalResult').innerHTML = 
                        `🎉 Success! Original text recovered: <strong>${workflowData.finalResult}</strong>`;
                    
                    updateStepStatus(8, 'completed');
                }, 500);
            }, 1000);
        }, 1000);
    }, 500);
}

function resetWorkflow() {
    // Reset data
    workflowData = {
        plainText: "",
        originalTextLength: 0,
        hillKey: [[3, 2], [5, 7]],
        hillEncrypted: "",
        hillBits: "",
        sdesKey: "1010000010",
        sdesEncrypted: "",
        coverImage: null,
        stegoImage: null,
        extractedBits: "",
        sdesDecrypted: "",
        hillDecrypted: "",
        finalResult: ""
    };
    
    currentStep = 1;
    
    // Reset UI
    for (let i = 1; i <= 8; i++) {
        const stepCard = document.getElementById(`step${i}`);
        stepCard.classList.remove('active', 'completed', 'processing');
        
        const resultDiv = stepCard.querySelector('.result-display');
        if (resultDiv) {
            resultDiv.classList.remove('show');
            resultDiv.innerHTML = '';
        }
    }
    
    // Clear inputs
    document.getElementById('plaintext').value = '';
    document.getElementById('imageInput').value = '';
    document.getElementById('finalResult').innerHTML = '';
    
    // Clear canvases
    const originalCanvas = document.getElementById('originalCanvas');
    const stegoCanvas = document.getElementById('stegoCanvas');
    const ctx1 = originalCanvas.getContext('2d');
    const ctx2 = stegoCanvas.getContext('2d');
    ctx1.clearRect(0, 0, originalCanvas.width, originalCanvas.height);
    ctx2.clearRect(0, 0, stegoCanvas.width, stegoCanvas.height);
    
    alert('Workflow reset successfully!');
}

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    console.log('Cryptographic Workflow Application Initialized');
});
