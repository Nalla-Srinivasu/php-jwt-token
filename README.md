JWT TOKEN used by firebase php-jwt

        follow the steps:
        -install composer
        -composer init
        -Use composer to manage your dependencies and download PHP-JWT:
        -composer require firebase/php-jwt


    ---------- firbase jwt ------------
    https://github.com/firebase/php-jwt/tree/main?tab=readme-ov-file
    
      Description:
      -loads the Composer autoloader through the firebase JWT library.
      -imports the JWT class from the firebase JWT library.
      -secret key used to sign the token, key is private.
      -generate a token: This function generates a JWT token.
      -$uniqueId: generates a unique ID for the token using random_bytes.
      -$payload: The data encoded into the JWT token. It includes:
        iss: Issuer of the token(domain URL).
        aud: Audience of the token(domain URL).
        iat: Issued at time.
          nbf: Not before time.
          exp: Expiration time.
          data: Custom data, including userId, tokenId, and action.
          JWT::encode($payload, $key, 'HS256'): This encodes the payload into a JWT token using the particular key and algorithm (HS256).
    
        ->bin2hex() is a built-in PHP function. It converts a string of ASCII characters to hexadecimal values.
        ->pack() string can be converted back using the pack() function.This also bult-in php function.

	->Validating token:
    ->The JWT::decode function decodes the token using the same key and algorithm(HS256).
    ->Token is checks whether the token is expired or not by comparing the current time with the exp claim in the payload.
    ->token id checks and action name also checks wthin the token.
    ->If the token is valid then we access the page.
