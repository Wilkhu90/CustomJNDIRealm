package com.sumeet.realm;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import org.apache.coyote.http11.Http11Nio2Protocol;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.stream.Stream;

public class CustomHttp11Nio2Protocol extends Http11Nio2Protocol {

    /**
     *  Hashicorp Vault URL
     */
    protected String vaultUrl = "https://vault.link.com";

    /**
     *  Hashicorp Vault token
     */
    protected String vaultToken = "";

    @Override
    public void setKeystorePass(String certificateKeystorePassword) {
        super.setKeystorePass(getServiceAccountPassword());
    }

    protected String getServiceAccountPassword() {
        try {

            VaultConfig vaultConfig = new VaultConfig()
                    .address(vaultUrl)
                    .token(vaultToken)
                    .build();
            Vault vault = new Vault(vaultConfig);
            String password = vault.logical()
                    .read("cubbyhole/keystore_pass")
                    .getData()
                    .get("password");

            return password;
        } catch (VaultException ve) {
            System.out.println("Vault seems to be unavailable at the moment.");
        } finally {
            try {
                String encyptedPass = readFile("/Library/Tomcat/encryptedKeystorePass.txt");
                //containerLog.info(encyptedPass);
                AESAlgorithm aesAlgorithm = new AESAlgorithm();
                String password = aesAlgorithm.decrypt(encyptedPass.replace("\n", "").trim().toString());
                //containerLog.info(password);
                return password;
            } catch (Exception e) {
                System.out.println("The encrypted password was not fetched.");
            }
        }
        return null;
    }

    protected String readFile(String filePath) {
        StringBuilder contentBuilder = new StringBuilder();

        try (Stream<String> stream = Files.lines( Paths.get(filePath), StandardCharsets.UTF_8)) {
            stream.forEach(s -> contentBuilder.append(s).append("\n"));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return contentBuilder.toString();
    }
}
