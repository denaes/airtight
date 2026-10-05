const credentialsHeader = "Access-Control-Allow-Credentials: true";

// Case 1: object literal with wildcard origin
const corsHeaders1 = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Credentials": "true",
};

// Case 2: set method with wildcard origin
headers.set("Access-Control-Allow-Origin", "*");

// Case 3: single quotes with wildcard origin
const corsHeaders2 = {
  'Access-Control-Allow-Origin': '*',
};

// Case 4: append method with wildcard origin
response.headers.append("Access-Control-Allow-Origin", "*");
