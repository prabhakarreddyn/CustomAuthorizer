package lambda.apigateway.authorizer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;

public class LambdaFunctionHandler implements RequestHandler<Map<String, Object>, Map<String, Object>> {

	@Override
	public Map<String, Object> handleRequest(Map<String, Object> input, Context context) {
		context.getLogger().log("Input: " + input);
		String token = input.get("authorizationToken").toString();
		ClassLoader classLoader = getClass().getClassLoader();
		File cityFile = new File(classLoader.getResource("application.properties").getFile());
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(cityFile);
			BufferedReader wbf = new BufferedReader(new InputStreamReader(fis));
			String wfl = "";
			while ((wfl = wbf.readLine()) != null) {
				if (wfl.contains("Authorization")) {
					String[] str = wfl.split("=");
					List<String> properyFilePathGroups = Arrays.asList(str[1]);
					String authToken = properyFilePathGroups.get(0);
					if(authToken.equals(token)){
						return generatePolicy("123", "Allow", input.get("methodArn").toString());
					}
					else{
						return generatePolicy("2001", "Deny", input.get("methodArn").toString());
					}
				}
			}

			}
		catch (Exception e) {
			e.printStackTrace();
		}
		return input;
	}

	private Map<String, Object> generatePolicy(String principalId, String effect, String resource) {
		Map<String, Object> authResponse = new HashMap<>();
		authResponse.put("principalId", principalId);
		Map<String, Object> policyDocument = new HashMap<>();
		policyDocument.put("Version", "2012-10-17"); // default version
		Map<String, String> statementOne = new HashMap<>();
		statementOne.put("Action", "execute-api:Invoke"); // default action
		statementOne.put("Effect", effect);
		statementOne.put("Resource", resource);
		policyDocument.put("Statement", new Object[] { statementOne });
		authResponse.put("policyDocument", policyDocument);
		if ("Allow".equals(effect)) {
			Map<String, Object> context = new HashMap<>();
			context.put("key", "AuthorizedUser");
			context.put("numKey", Long.valueOf(1L));
			context.put("boolKey", Boolean.TRUE);
			authResponse.put("context", context);
		}
		else{
			
			Map<String, Object> context = new HashMap<>();
			context.put("key", "UnauthorizedUser");
			context.put("numKey", Long.valueOf(1L));
			context.put("boolKey", Boolean.FALSE);
			authResponse.put("context", context);
			
		}
		return authResponse;
	}

}
