% TestKasumiCipher.m
% Script pentru testarea implementării KasumiCipher

% Date de intrare (ca string-uri hexazecimale)
keyHex = '80000000000000000000000000000000';
textHex = '0000000000000000';

% Conversie text clar la uint64 fără pierdere de precizie
text = uint64(sscanf(textHex, '%lx'));

% Afișare date de intrare
fprintf('Data is 0x%s\n', upper(textHex));
fprintf('Key is 0x%s\n', upper(keyHex));

% Inițializare și setare cheie
kasumi = KasumiCipher();
kasumi = kasumi.setKey(keyHex);

% Criptare inițială
encrypted = kasumi.encrypt(text);
fprintf('encrypted 0x%s\n', upper(dec2hex(encrypted, 16)));

% Bucle de testare: 99 criptări, apoi 99 decriptări
tempVal = encrypted;
for i = 1:99
    tempVal = kasumi.encrypt(tempVal);
end
for i = 1:99
    tempVal = kasumi.decrypt(tempVal);
end

% Decriptare finală
decrypted = kasumi.decrypt(tempVal);
fprintf('decrypted 0x%s\n', upper(dec2hex(decrypted, 16)));

% Verificare
if isequal(dec2hex(decrypted, 16), upper(textHex))
    fprintf('Test PASSED: Decrypted data matches original text.\n');
else
    fprintf('Test FAILED: Decrypted data does NOT match original text.\n');
    fprintf('Expected decrypted: 0x%s\n', upper(textHex));
    fprintf('Actual decrypted:   0x%s\n', upper(dec2hex(decrypted, 16)));
end

% Afișare rezultat așteptat pentru criptare (pentru comparație)
fprintf('Expected encrypted: 0x514896226CAA4F20\n');