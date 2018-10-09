package com.sumeet.realm;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import oracle.jdbc.driver.OracleDriver;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;
import java.util.stream.Stream;

public class CustomOracleDriver extends OracleDriver {

    /**
     *  Hashicorp Vault URL
     */
    protected String vaultUrl = "https://vault.link.com";

    /**
     *  Hashicorp Vault token
     */
    protected String vaultToken = "xxx-xxx";

    @Override
    public Connection connect(String s, Properties properties) throws SQLException {
        properties.setProperty("password", getServiceAccountPassword(properties.getProperty("user")));
        return super.connect(s, properties);
    }

    protected String getServiceAccountPassword(String serviceAccountName) {
        try {

            VaultConfig vaultConfig = new VaultConfig()
                    .address(vaultUrl)
                    .token(vaultToken)
                    .build();
            Vault vault = new Vault(vaultConfig);
            String password = vault.logical()
                    .read("cubbyhole/"+serviceAccountName)
                    .getData()
                    .get("password");

            return password;
        } catch (VaultException ve) {
            ;
        } finally {
            try {
                String encyptedPass = readFile("/Library/Tomcat/encryptedAccountPass.txt");
                //containerLog.info(encyptedPass);
                AESAlgorithm aesAlgorithm = new AESAlgorithm();
                String password = aesAlgorithm.decrypt(encyptedPass.replace("\n", "").trim().toString());
                //containerLog.info(password);
                return password;
            } catch (Exception e) {
                ;
            }
        }
        return null;
    }

    protected String readFile(String filePath)
    {
        StringBuilder contentBuilder = new StringBuilder();

        try (Stream<String> stream = Files.lines( Paths.get(filePath), StandardCharsets.UTF_8)) {
            stream.forEach(s -> contentBuilder.append(s).append("\n"));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return contentBuilder.toString();
    }
}
