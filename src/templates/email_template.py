# src/templates/email_template.py

class EmailTemplate:
    @staticmethod
    def get_hotel_info():
        return """Red Roof Inn, Moss Point
- Weekly Rates: $370 (Single Bed) / $420 (Double Bed) including tax
- Monthly Rates: $50 (Single Bed) / $57 (Double Bed) per night including tax, for stays of one month or longer

Distinguished Amenities:
- Complimentary hot breakfast featuring scrambled eggs and sausage gravy
- Newly renovated rooms with modern furniture
- Complimentary Tesla and EV charging stations
- High-speed Wi-Fi
- 24/7 coffee service in the lobby
- Strategic location in Moss Point
- Business-friendly facilities
- Corporate rewards program"""

    @staticmethod
    def get_contact_info():
        return """Kathan Patel
General Manager
Tel: +1(228) 460-0615
Email: Redroofinn1101@gmail.com or Sale.rrimp@gmail.com"""
    
    @staticmethod
    def create_email_content(contact_info):
        subject = f"Exclusive Corporate Rates - Red Roof Inn Moss Point for {contact_info['company_name']}"
        
        body = f"""Dear Sir/Madam,

I trust this letter finds you well. I am writing to introduce the exclusive corporate rates available at Red Roof Inn, Moss Point, designed specifically for {contact_info['company_name']}'s contractors and workforce.

We understand that business travelers have unique requirements, and we are committed to providing exceptional accommodations at competitive rates. Our partnership with CLC Lodging enables us to offer particularly attractive pricing for both short-term and extended stays.

Our Corporate Rate Structure:
{EmailTemplate.get_hotel_info()}

For companies with specific room requirements and employee headcounts, we are happy to discuss custom rate negotiations to better accommodate your needs. Our flexible pricing structure allows us to provide even more competitive rates for larger groups or longer-term commitments.

As a CLC Lodging partner, we are positioned to provide superior accommodations at highly competitive rates. We welcome the opportunity to discuss how we can tailor our services to meet your specific requirements.

For reservations or inquiries, please contact:
{EmailTemplate.get_contact_info()}

We look forward to establishing a lasting partnership with {contact_info['company_name']} and serving as your preferred accommodation provider.

Best regards,
Kathan Patel
General Manager
Red Roof Inn, Moss Point"""
        
        return subject, body

    @staticmethod
    def create_follow_up_content(contact_info):
        """Optional method for follow-up emails"""
        subject = f"Following Up - Corporate Rates at Red Roof Inn Moss Point for {contact_info['company_name']}"
        
        body = f"""Dear Sir/Madam,

I hope you received our previous email regarding the exclusive corporate rates at Red Roof Inn, Moss Point. I wanted to follow up and see if you have any questions about our offerings for {contact_info['company_name']}.

Our competitive rates and business-friendly amenities make us an ideal choice for your corporate housing needs. I would be happy to discuss how we can create a custom package that best suits your requirements.

For your reference, our corporate rates are:
{EmailTemplate.get_hotel_info()}

Please don't hesitate to reach out if you would like to discuss this further or schedule a property tour.

{EmailTemplate.get_contact_info()}

Best regards,
Kathan Patel
General Manager
Red Roof Inn, Moss Point"""

        return subject, body