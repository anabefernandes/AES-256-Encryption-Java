package fatec.gov.br.aes;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

/**
 * aesgcmpkcs7demo
 *
 * esse código é um teste pra entender como o aes-256 funciona na prática
 * ele gera uma chave, lê uma mensagem do usuário, aplica padding se precisar,
 * criptografa com aes-256-gcm e depois descriptografa pra mostrar que funciona
 *
 * gcm é um modo de operação que já traz autenticação junto, então ele é bem seguro
 * o iv é um número aleatório que precisa ser único a cada criptografia
 * o padding pkcs#7 foi adicionado só pra garantir o tamanho mínimo de 16 bytes
 */

public class AesGcmPkcs7Demo {

    // aqui foi definido os tamanhos usados pelo aes
    private static final int AES_KEY_BITS = 256;   // tamanho da chave (256 bits)
    private static final int IV_SIZE_BYTES = 12;   // tamanho do iv (12 bytes é o recomendado no modo gcm)
    private static final int GCM_TAG_BITS = 128;   // tamanho da tag de autenticação (em bits)
    private static final int BLOCK_SIZE = 16;      // tamanho do bloco do aes (16 bytes)

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8);

        System.out.println("digite uma mensagem (mínimo 16 bytes; se menor, aplico pkcs#7):");
        String input = scanner.nextLine();
        byte[] plaintext = input.getBytes(StandardCharsets.UTF_8);
        System.out.println("texto original: " + input);

        // aqui verifica se o texto precisa de padding pra completar o tamanho do bloco
        // o padding pkcs#7 serve pra completar o último bloco quando o texto não tem tamanho múltiplo de 16 bytes
        boolean padded = false;
        byte[] paddedPlaintext = plaintext;
        if (plaintext.length < BLOCK_SIZE || (plaintext.length % BLOCK_SIZE) != 0) {
            paddedPlaintext = applyPkcs7Padding(plaintext, BLOCK_SIZE);
            padded = true;
            System.out.println("padding pkcs#7 aplicado. tamanho antes: " + plaintext.length +
                    " bytes, com padding: " + paddedPlaintext.length + " bytes.");
        } else {
            System.out.println("não precisei aplicar padding, o tamanho já está certo.");
        }

        // gerar uma chave aes de 256 bits
        // essa chave é o segredo principal usado pra criptografar e descriptografar
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_BITS);
        SecretKey key = keyGen.generateKey();
        System.out.println("chave aes-256 gerada (base64): " + Base64.getEncoder().encodeToString(key.getEncoded()));
        // obs: normalmente a chave nunca deve ser mostrada, aqui é só pra teste mesmo

        // agora gera o iv (vetor de inicialização), que é um número aleatório usado junto com a chave
        // ele garante que, mesmo se criptografar a mesma mensagem duas vezes, o resultado vai ser diferente
        byte[] iv = new byte[IV_SIZE_BYTES];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(iv);
        System.out.println("iv gerado (base64): " + Base64.getEncoder().encodeToString(iv));
        // o iv não é segredo, mas tem que ser diferente a cada vez que criptografar

        // agora cria o objeto cipher, que é o que realmente faz a criptografia
        // aqui uso o modo aes/gcm/nopadding (gcm = modo de operação com autenticação)
        Cipher encryptCipher = Cipher.getInstance("AES/GCM/NoPadding");

        // o gcmparameterspec define o tamanho da tag de autenticação e o iv que vai ser usado
        // a tag é usada pra garantir que o conteúdo não foi alterado
        GCMParameterSpec gcmSpecEnc = new GCMParameterSpec(GCM_TAG_BITS, iv);

        // inicializar o cipher no modo de criptografia, passando a chave e o iv
        encryptCipher.init(Cipher.ENCRYPT_MODE, key, gcmSpecEnc);

        // se quiser autenticar dados extras (que não são criptografados), usaria updateaad()
        // ex: encryptCipher.updateAAD("cabeçalho".getBytes());
        // nesse caso não usamos, só deixamos o exemplo
        // o aad é "additional authenticated data", garante integridade mas não é secreto

        // aqui o cipher faz a criptografia de fato
        // o resultado final (ciphertext) já inclui a tag de autenticação no final
        byte[] cipherBytes = encryptCipher.doFinal(paddedPlaintext);
        String cipherBase64 = Base64.getEncoder().encodeToString(cipherBytes);
        System.out.println("mensagem criptografada (base64): " + cipherBase64);

        // agora cria outro cipher pra descriptografar
        // ele precisa usar o mesmo modo, a mesma chave e o mesmo iv
        Cipher decryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpecDec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        decryptCipher.init(Cipher.DECRYPT_MODE, key, gcmSpecDec);

        // se tivesse usado aad antes, precisaria repetir aqui pra validar
        // decryptCipher.updateAAD(...)

        // aqui acontece a descriptografia, transformando o texto criptografado de volta pro original
        byte[] decryptedPadded = decryptCipher.doFinal(Base64.getDecoder().decode(cipherBase64));
        System.out.println("descriptografia concluída. tamanho: " + decryptedPadded.length + " bytes");

        // se tinha padding antes, agora remove pra recuperar o texto original
        byte[] decrypted;
        if (padded) {
            decrypted = removePkcs7Padding(decryptedPadded, BLOCK_SIZE);
            System.out.println("padding pkcs#7 removido após descriptografia.");
        } else {
            decrypted = decryptedPadded;
        }

        // converter os bytes descriptografados de volta pra string legível
        String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
        System.out.println("texto descriptografado: " + decryptedText);

        // aqui compara pra ver se o texto original e o descriptografado são iguais
        if (Arrays.equals(plaintext, decrypted)) {
            System.out.println("validação: texto original e descriptografado são iguais ✅");
        } else {
            System.out.println("validação: texto original e descriptografado diferem ❌");
        }
    }

    // essa função adiciona padding pkcs#7
    // ela serve pra completar o último bloco até chegar em 16 bytes
    private static byte[] applyPkcs7Padding(byte[] data, int blockSize) {
        int padLen = blockSize - (data.length % blockSize);
        if (padLen == 0) padLen = blockSize;
        byte padByte = (byte) padLen;

        byte[] padded = Arrays.copyOf(data, data.length + padLen);
        for (int i = data.length; i < padded.length; i++) {
            padded[i] = padByte;
        }
        return padded;
    }

    // essa função remove o padding pkcs#7 depois da descriptografia
    // ela verifica os bytes extras e corta fora pra voltar o texto original
    private static byte[] removePkcs7Padding(byte[] paddedData, int blockSize) throws Exception {
        if (paddedData.length == 0 || paddedData.length % blockSize != 0) {
            throw new Exception("tamanho inválido para remover pkcs#7.");
        }

        int padLen = paddedData[paddedData.length - 1] & 0xFF;
        if (padLen < 1 || padLen > blockSize) {
            throw new Exception("padding pkcs#7 inválido.");
        }

        // aqui só confira se o padding é válido (não obrigatório, mas é bom pra garantir)
        for (int i = paddedData.length - padLen; i < paddedData.length; i++) {
            if (paddedData[i] != (byte) padLen) {
                throw new Exception("erro ao validar padding pkcs#7.");
            }
        }

        // retorno o texto original sem o padding
        return Arrays.copyOf(paddedData, paddedData.length - padLen);
    }
}
