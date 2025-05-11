% KasumiCipher.m
% Implementarea cifrului bloc Kasumi în MATLAB

classdef KasumiCipher
    properties (Constant)
        % S-box S7: 128 elemente (7 biți)
        S7 = uint8([ ...
            54, 50, 62, 56, 22, 34, 94, 96, 38,  6, 63, 93, 2,  18,123, 33, ...
            55,113, 39,114, 21, 67, 65, 12, 47, 73, 46, 27, 25,111,124, 81, ...
            53,  9,121, 79, 52, 60, 58, 48,101,127, 40,120,104, 70, 71, 43, ...
            20,122, 72, 61, 23,109, 13,100, 77,  1, 16,  7, 82, 10,105, 98, ...
           117,116, 76, 11, 89,106,  0,125,118, 99, 86, 69, 30, 57,126, 87, ...
           112, 51, 17,  5, 95, 14, 90, 84, 91,  8, 35,103, 32, 97, 28, 66, ...
           102, 31, 26, 45, 75,  4, 85, 92, 37, 74, 80, 49, 68, 29,115, 44, ...
            64,107,108, 24,110, 83, 36, 78, 42, 19, 15, 41, 88,119, 59,  3 ...
        ]);

        % S-box S9: 512 elemente (9 biți)
        S9 = uint16([ ...
            167,239,161,379,391,334,  9,338, 38,226, 48,358,452,385, 90,397, ...
            183,253,147,331,415,340, 51,362,306,500,262, 82,216,159,356,177, ...
            175,241,489, 37,206, 17,  0,333, 44,254,378, 58,143,220, 81,400, ...
             95,  3,315,245, 54,235,218,405,472,264,172,494,371,290,399, 76, ...
            165,197,395,121,257,480,423,212,240, 28,462,176,406,507,288,223, ...
            501,407,249,265, 89,186,221,428,164, 74,440,196,458,421,350,163, ...
            232,158,134,354, 13,250,491,142,191, 69,193,425,152,227,366,135, ...
            344,300,276,242,437,320,113,278, 11,243, 87,317, 36, 93,496, 27, ...
            487,446,482, 41, 68,156,457,131,326,403,339, 20, 39,115,442,124, ...
            475,384,508, 53,112,170,479,151,126,169, 73,268,279,321,168,364, ...
            363,292, 46,499,393,327,324, 24,456,267,157,460,488,426,309,229, ...
            439,506,208,271,349,401,434,236, 16,209,359, 52, 56,120,199,277, ...
            465,416,252,287,246,  6, 83,305,420,345,153,502, 65, 61,244,282, ...
            173,222,418, 67,386,368,261,101,476,291,195,430, 49, 79,166,330, ...
            280,383,373,128,382,408,155,495,367,388,274,107,459,417, 62,454, ...
            132,225,203,316,234, 14,301, 91,503,286,424,211,347,307,140,374, ...
             35,103,125,427, 19,214,453,146,498,314,444,230,256,329,198,285, ...
             50,116, 78,410, 10,205,510,171,231, 45,139,467, 29, 86,505, 32, ...
             72, 26,342,150,313,490,431,238,411,325,149,473, 40,119,174,355, ...
            185,233,389, 71,448,273,372, 55,110,178,322, 12,469,392,369,190, ...
              1,109,375,137,181, 88, 75,308,260,484, 98,272,370,275,412,111, ...
            336,318,  4,504,492,259,304, 77,337,435, 21,357,303,332,483, 18, ...
             47, 85, 25,497,474,289,100,269,296,478,270,106, 31,104,433, 84, ...
            414,486,394, 96, 99,154,511,148,413,361,409,255,162,215,302,201, ...
            266,351,343,144,441,365,108,298,251, 34,182,509,138,210,335,133, ...
            311,352,328,141,396,346,123,319,450,281,429,228,443,481, 92,404, ...
            485,422,248,297, 23,213,130,466, 22,217,283, 70,294,360,419,127, ...
            312,377,  7,468,194,  2,117,295,463,258,224,447,247,187, 80,398, ...
            284,353,105,390,299,471,470,184, 57,200,348, 63,204,188, 33,451, ...
             97, 30,310,219, 94,160,129,493, 64,179,263,102,189,207,114,402, ...
            438,477,387,122,192, 42,381,  5,145,118,180,449,293,323,136,380, ...
             43, 66, 60,455,341,445,202,432,  8,237, 15,376,436,464, 59,461 ...
        ]);
    end

    properties (Access = private)
        % Subchei pe 16 biți pentru fiecare rundă (8 runde)
        subkeyKL1 % Pentru funcția FL
        subkeyKL2 % Pentru funcția FL
        subkeyKO1 % Pentru funcția FO (FI)
        subkeyKO2 % Pentru funcția FO (FI)
        subkeyKO3 % Pentru funcția FO (FI)
        subkeyKI1 % Pentru funcția FI
        subkeyKI2 % Pentru funcția FI
        subkeyKI3 % Pentru funcția FI
    end

    methods (Static, Access = private)
        function len = bitlen(x)
            % Calculează lungimea în biți a unui număr
            assert(x >= 0, 'Input must be non-negative');
            if x == 0
                len = 1;
            else
                len = numel(dec2bin(x));
            end
        end

        function res = shift(x, s)
            % Deplasare circulară la stânga pentru un număr pe 16 biți
            assert(KasumiCipher.bitlen(x) <= 16, 'Input must be at most 16 bits');
            x_u16 = uint16(x);
            s_eff = mod(s, 16);
            res = bitor(bitshift(x_u16, s_eff), bitshift(x_u16, s_eff - 16));
        end

        function res = modIndex(x)
            % Calculează ((x - 1) % 8) + 1 pentru indexare
            res = mod(x - 1, 8) + 1;
        end
    end

    methods
        function obj = KasumiCipher()
            % Constructor: Inițializează subcheile ca vectori de 8 elemente uint16
            obj.subkeyKL1 = zeros(1, 8, 'uint16');
            obj.subkeyKL2 = zeros(1, 8, 'uint16');
            obj.subkeyKO1 = zeros(1, 8, 'uint16');
            obj.subkeyKO2 = zeros(1, 8, 'uint16');
            obj.subkeyKO3 = zeros(1, 8, 'uint16');
            obj.subkeyKI1 = zeros(1, 8, 'uint16');
            obj.subkeyKI2 = zeros(1, 8, 'uint16');
            obj.subkeyKI3 = zeros(1, 8, 'uint16');
        end

        function obj = setKey(obj, masterKeyHex)
            % Setează cheia master și generează subcheile
            % masterKeyHex: string hexazecimal de 32 caractere (128 biți)
            assert(length(masterKeyHex) == 32, 'Master key must be 128 bits (32 hex characters)');

            key = zeros(1, 8, 'uint16');
            keyPrime = zeros(1, 8, 'uint16');

            % Constanta XOR din specificația Kasumi
            keyConstXorHex = '0123456789ABCDEFFEDCBA9876543210';

            % Procesare cheie pe bucăți de 16 biți
            for i = 1:8
                startIdx = (i-1)*4 + 1;
                keyChunk = masterKeyHex(startIdx:startIdx+3);
                key(i) = uint16(hex2dec(keyChunk));

                constChunk = keyConstXorHex(startIdx:startIdx+3);
                keyPrime(i) = bitxor(key(i), uint16(hex2dec(constChunk)));
            end

            % Generează subcheile
            for i = 1:8
                obj.subkeyKL1(i) = KasumiCipher.shift(key(KasumiCipher.modIndex(i + 0)), 1);
                obj.subkeyKL2(i) = keyPrime(KasumiCipher.modIndex(i + 2));
                obj.subkeyKO1(i) = KasumiCipher.shift(key(KasumiCipher.modIndex(i + 1)), 5);
                obj.subkeyKO2(i) = KasumiCipher.shift(key(KasumiCipher.modIndex(i + 5)), 8);
                obj.subkeyKO3(i) = KasumiCipher.shift(key(KasumiCipher.modIndex(i + 6)), 13);
                obj.subkeyKI1(i) = keyPrime(KasumiCipher.modIndex(i + 4));
                obj.subkeyKI2(i) = keyPrime(KasumiCipher.modIndex(i + 3));
                obj.subkeyKI3(i) = keyPrime(KasumiCipher.modIndex(i + 7));
            end
        end

        function output = applyFI(obj, input, roundKey)
            % Funcția FI: Procesează 16 biți cu S-box-urile S7 și S9
            input_u16 = uint16(input);
            roundKey_u16 = uint16(roundKey);

            left = bitshift(input_u16, -7); % 9 biți superiori
            right = bitand(input_u16, uint16(127)); % 7 biți inferiori (0b1111111)

            roundKey1 = bitshift(roundKey_u16, -9); % 7 biți superiori
            roundKey2 = bitand(roundKey_u16, uint16(511)); % 9 biți inferiori (0b111111111)

            % Primul nivel
            tempLeft = right;
            tempRight = bitxor(uint16(obj.S9(left + 1)), tempLeft);

            % Al doilea nivel
            left = bitxor(tempRight, roundKey2);
            valS7 = uint16(obj.S7(tempLeft + 1));
            right = bitxor(valS7, bitand(tempRight, uint16(127)));
            right = bitxor(right, roundKey1);

            % Al treilea nivel
            tempLeft = right;
            tempRight = bitxor(uint16(obj.S9(left + 1)), tempLeft);

            valS7 = uint16(obj.S7(tempLeft + 1));
            left = bitxor(valS7, bitand(tempRight, uint16(127)));
            right = tempRight;

            output = bitor(bitshift(uint16(left), 9), uint16(right));
        end

        function output = applyFO(obj, input, roundIndex)
            % Funcția FO: Aplica FI de trei ori
            input_u32 = uint32(input);

            inLeft = uint16(bitshift(input_u32, -16));
            inRight = uint16(bitand(input_u32, hex2dec('FFFF')));

            % Pasul 1
            outLeft = inRight;
            outRight = bitxor(obj.applyFI(bitxor(inLeft, obj.subkeyKO1(roundIndex)), ...
                                         obj.subkeyKI1(roundIndex)), inRight);

            % Pasul 2
            tempLeft = outRight;
            tempRight = bitxor(obj.applyFI(bitxor(outLeft, obj.subkeyKO2(roundIndex)), ...
                                          obj.subkeyKI2(roundIndex)), outRight);

            % Pasul 3
            outLeft = tempRight;
            outRight = bitxor(obj.applyFI(bitxor(tempLeft, obj.subkeyKO3(roundIndex)), ...
                                          obj.subkeyKI3(roundIndex)), tempRight);

            output = bitor(bitshift(uint32(outLeft), 16), uint32(outRight));
        end

        function output = applyFL(obj, input, roundIndex)
            % Funcția FL: Aplica operații AND, OR și deplasări
            input_u32 = uint32(input);

            inLeft = uint16(bitshift(input_u32, -16));
            inRight = uint16(bitand(input_u32, hex2dec('FFFF')));

            outRight = bitxor(inRight, KasumiCipher.shift(bitand(inLeft, obj.subkeyKL1(roundIndex)), 1));
            outLeft = bitxor(inLeft, KasumiCipher.shift(bitor(outRight, obj.subkeyKL2(roundIndex)), 1));

            output = bitor(bitshift(uint32(outLeft), 16), uint32(outRight));
        end

        function output = applyRoundFunction(obj, input, roundIndex)
            % Funcția f: Combină FL și FO în funcție de runda (impară/pară)
            if mod(roundIndex, 2) == 1
                state = obj.applyFL(input, roundIndex);
                output = obj.applyFO(state, roundIndex);
            else
                state = obj.applyFO(input, roundIndex);
                output = obj.applyFL(state, roundIndex);
            end
        end

        function [outLeft, outRight] = encryptOneRound(obj, inLeft, inRight, roundIndex)
            % Criptare pentru o rundă
            outRight = inLeft;
            outLeft = bitxor(inRight, obj.applyRoundFunction(inLeft, roundIndex));
        end

        function [outLeft, outRight] = decryptOneRound(obj, inLeft, inRight, roundIndex)
            % Decriptare pentru o rundă
            outLeft = inRight;
            outRight = bitxor(obj.applyRoundFunction(inRight, roundIndex), inLeft);
        end

        function ciphertext = encrypt(obj, plaintext)
            % Criptează un bloc de 64 biți
            assert(KasumiCipher.bitlen(plaintext) <= 64, 'Plaintext must be at most 64 bits');

            % Converti plaintext la uint64 și împarte în două jumătăți de 32 biți
            plaintext_u64 = uint64(plaintext);
            left_u32 = uint32(bitshift(plaintext_u64, -32));
            right_u32 = uint32(bitand(plaintext_u64, uint64(hex2dec('FFFFFFFF'))));

          

            % Aplica cele 8 runde
            for i = 1:8
                [left_u32, right_u32] = obj.encryptOneRound(left_u32, right_u32, i);
                
            end

            % Combină jumătățile pentru a forma ciphertext
            ciphertext = bitor(bitshift(uint64(left_u32), 32), uint64(right_u32));
        end

        function plaintext = decrypt(obj, ciphertext)
            % Decriptează un bloc de 64 biți
            assert(KasumiCipher.bitlen(ciphertext) <= 64, 'Ciphertext must be at most 64 bits');

            % Converti ciphertext la uint64 și împarte în două jumătăți de 32 biți
            ciphertext_u64 = uint64(ciphertext);
            left_u32 = uint32(bitshift(ciphertext_u64, -32));
            right_u32 = uint32(bitand(ciphertext_u64, uint64(hex2dec('FFFFFFFF'))));

            

            % Aplica cele 8 runde în ordine inversă
            for i = 8:-1:1
                [left_u32, right_u32] = obj.decryptOneRound(left_u32, right_u32, i);

            end

            % Combină jumătățile pentru a forma plaintext
            plaintext = bitor(bitshift(uint64(left_u32), 32), uint64(right_u32));
        end
    end
end