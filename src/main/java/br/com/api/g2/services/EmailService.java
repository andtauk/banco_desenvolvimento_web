package br.com.api.g2.services;

import java.util.Properties;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import br.com.api.g2.domain.Pedido;
import br.com.api.g2.domain.Produto;
import br.com.api.g2.dto.UsuarioDTO;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

@Service
public class EmailService {
	
	@Autowired
    JavaMailSender emailSender;

    @Bean
    public JavaMailSender javaMailSender() {
        JavaMailSenderImpl emailSender = new JavaMailSenderImpl();
        Properties properties = new Properties();

        emailSender.setHost("smtp.gmail.com");
        emailSender.setPort(587);
        emailSender.setUsername("trabalhoapigrupo2@gmail.com");
        emailSender.setPassword("vnpvqkgepjadrbpe");
        properties.put("mail.smtp.auth", true);
        properties.put("mail.smtp.starttls.enable", true);
        emailSender.setJavaMailProperties(properties);

        return emailSender;
    }

    //Método para envio de email de produto cadastrado
    public void envioEmailProdutoCadastrado(String email, Produto produto) throws MessagingException {
        this.emailSender = javaMailSender();
        MimeMessage messageProduto = emailSender.createMimeMessage();
        MimeMessageHelper helperProduto = new MimeMessageHelper(messageProduto, true);

        try {
        	helperProduto.setFrom("trabalhoapigrupo2@gmail.com");
        	helperProduto.setTo(email);
        	helperProduto.setSubject(email);

            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append("<html>\r\n");
            stringBuilder.append("   <body>\r\n");
            stringBuilder.append("      <div align=\"center\">\r\n");
            stringBuilder.append("          <h1>Produto cadastrado com sucesso!</h1>\r\n");
            stringBuilder.append("          <p>Agradecemos pelo cadastro em nossa loja.</p>\r\n");
            stringBuilder.append("      </div>\r\n");
            stringBuilder.append("   </body>\r\n");
            stringBuilder.append("</html>\r\n");

            helperProduto.setText(stringBuilder.toString(), true);
            emailSender.send(messageProduto);

        }
        catch(Exception e){
            e.printStackTrace();
        }
    }
    
    public void envioEmailUsuarioCadastrado(String email, UsuarioDTO usuarioDTO) throws MessagingException {
        this.emailSender = javaMailSender();
        MimeMessage messageUsuario = emailSender.createMimeMessage();
        MimeMessageHelper helperUsuario = new MimeMessageHelper(messageUsuario, true);

        try {
            helperUsuario.setFrom("trabalhoapigrupo2@gmail.com");
            helperUsuario.setTo(email);
            helperUsuario.setSubject(email);

            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append("<html>\r\n");
            stringBuilder.append("   <body>\r\n");
            stringBuilder.append("      <div align=\"center\">\r\n");
            stringBuilder.append("          <h1>Usuário cadastrado com sucesso!</h1>\r\n");
            stringBuilder.append("          <p>Agradecemos pelo cadastro em nossa loja.</p>\r\n");
            stringBuilder.append("      </div>\r\n");
            stringBuilder.append("   </body>\r\n");
            stringBuilder.append("</html>\r\n");

            helperUsuario.setText(stringBuilder.toString(), true);
            emailSender.send(messageUsuario);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void envioEmailPedidoCadastrado(String email, Pedido pedido) throws MessagingException {
        this.emailSender = javaMailSender();
        MimeMessage messagePedido = emailSender.createMimeMessage();
        MimeMessageHelper helperPedido = new MimeMessageHelper(messagePedido, true);

        try {
            helperPedido.setFrom("trabalhoapigrupo2@gmail.com");
            helperPedido.setTo(email);
            helperPedido.setSubject(email);

            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append("<html>\r\n");
            stringBuilder.append("   <body>\r\n");
            stringBuilder.append("      <div align=\"center\">\r\n");
            stringBuilder.append("          <h1>Pedido cadastrado com sucesso!</h1>\r\n");
            stringBuilder.append("          <p>Agradecemos pelo seu pedido em nossa loja.</p>\r\n");
            stringBuilder.append("      </div>\r\n");
            stringBuilder.append("   </body>\r\n");
            stringBuilder.append("</html>\r\n");

            helperPedido.setText(stringBuilder.toString(), true);
            emailSender.send(messagePedido);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
