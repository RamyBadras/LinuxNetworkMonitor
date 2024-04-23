
    use lettre::message::header::ContentType;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{Message, SmtpTransport, Transport};
    
 pub fn send_mail(receiver_email: &str, subject: &str, body: &str) {
        let email = Message::builder()
            //.from("Name <sender's account>".parse().unwrap())
            .from("OS Project <shoay@aucegypt.edu>".parse().unwrap())
            .to(receiver_email.parse().unwrap())
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body.to_string())
            .unwrap();
    
        // Turn on the "allow less secure app" in Google Account Management
        //let creds = Credentials::new("<sender's account>".to_owned(), "your password".to_owned());
        let creds = Credentials::new("shaoy@aucegypt.edu".to_owned(), "Thankyou520!".to_owned());
    
        // Open a remote connection to gmail
        let mailer = SmtpTransport::relay("smtp.gmail.com")
            .unwrap()
            .credentials(creds)
            .build();
    
        // Send the email
        match mailer.send(&email) {
            Ok(_) => println!("Email sent successfully to {}!", receiver_email),
            Err(e) => panic!("Could not send email: {:?}", e),
        }
    }
    
 pub fn custom_email() {
        //let receiver_email = "Name <receipant's account>";
        let receiver_email = "Ramy <ramybadras@aucegypt.edu>";
        let subject = "Network Alert";
        let body = "Download exeeds 900KB.";
        send_mail(receiver_email, subject, body);
    }
    

