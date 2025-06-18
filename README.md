# jwthings

### **Resumo da Ferramenta**

**jwthings** é uma ferramenta voltada para testes de segurança em aplicações que utilizam **JSON Web Tokens (JWT)**. Sua principal funcionalidade é realizar **brute force de senhas utilizadas para assinar tokens JWT**, permitindo identificar chaves fracas ou previsíveis. Além disso, a ferramenta também oferece suporte para **geração e codificação de tokens (encode)**, o que facilita a criação de JWTs customizados durante testes.

#### **Funcionalidades principais:**

* **Brute force de senhas (HS256):** Testa listas de chaves conhecidas para quebrar a assinatura do JWT e identificar a chave secreta.
* **Geração/encode de JWTs:** Permite criar novos tokens a partir de payloads e segredos definidos pelo usuário.
* **Modo CLI:** Interface simples via linha de comando, ideal para integração com pipelines de pentest ou CTFs.

#### **Aplicações típicas:**

* Testes de segurança em APIs que usam JWT.
* Avaliação de políticas de geração de chaves JWT.
* Exploração de ambientes mal configurados.