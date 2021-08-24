# Token based authentication using Open Iddict without database
As of this application implemented using OpenIddict 3.0's degraded mode with Steam authentication integration. This implementation no need entity frame work and database connection. 

# Generating token using client credentials :
Server authenticated using client username,password and grant type. This call grant type must be a Password. Once valid details passed we can get token details

![image](https://user-images.githubusercontent.com/54973093/130559007-df0ad979-197f-43ba-a5fc-827638d9e5e5.png)

# Access authorized Controller :
Access authorized controller using the access token. This token is valid for 1 minute. Once time this token no longer valid.

![image](https://user-images.githubusercontent.com/54973093/130559150-9399027a-051a-4178-a09f-caa183870d40.png)

# Generate token using Refresh token :
Once access token invalid try to get access token via refresh token. This call grant type must be a refresh_token. Once valid refresh_token and grand type sent we can get token details. 

![image](https://user-images.githubusercontent.com/54973093/130559298-7ce74671-8524-40d3-9933-1019d1210dab.png)

# Token Life time :
As per this implementation access token valid 1 minute from creation time and refresh token will valid 4 minutes from creation time
![image](https://user-images.githubusercontent.com/54973093/130559975-d912a49a-59c6-4504-8288-413feb738944.png)




