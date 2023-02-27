package burp;
import com.alibaba.fastjson.JSONObject;

import javax.xml.bind.DatatypeConverter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.*;



public class BurpExtender implements IBurpExtender,IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    String key = "c3d881a19239e89bba2984eefbcd7596";
    String iv = "myInitialization";

//    byte[] keyBytes = key.getBytes("UTF-8");  //key = "mySecretKey12345";
     byte[] keyBytes = DatatypeConverter.parseHexBinary(key);  //key = "c3d881a19239e89bba2984eefbcd7596"
    byte[] ivBytes = iv.getBytes("UTF-8"); // iv = "myInitialization";
//    byte[] keyBytes = DatatypeConverter.parseHexBinary(iv);  //iv = "c3d881a19239e89bba2984eefbcd7596"

    public BurpExtender() throws UnsupportedEncodingException {
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        callbacks.setExtensionName("Crypt");
        String key = "mySecretKey12345";
        String iv = "myInitialization";
//        ArrayList linesRequestHeaders = new ArrayList<String>();
//        HashMap linesRequestBody = new HashMap<String, String>();
//        ArrayList linesResponseHeaders = new ArrayList<String>();
//        HashMap linesResponseBody = new HashMap<String, String>();

        callbacks.registerHttpListener((IHttpListener) this);
        // callbacks.registerProxyListener(this);
        String message = " ____   ___                        _        \n"
                + " |  _ \\ / _ \\  ___ _ __ _   _ _ __ | |_ ___  \n"
                + " | |_) | | | |/ __| '__| | | | '_ \\| __/ _ \\ \n"
                + " |  __/| |_| | (__| |  | |_| | |_) | || (_) |\n"
                + " |_|    \\___/ \\___|_|   \\__, | .__/ \\__\\___/ \n"
                + "                        |___/|_|             \n"
                + " ==== Start Encryption And Decryption! =====";
        this.stdout.println(message);
    }
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY || toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER) {
            if (messageIsRequest) { //if MessageInfo is request
                stdout.println("========================= Request Content Start! =========================");
                byte[] request = messageInfo.getRequest();
                IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
                String host = messageInfo.getHttpService().getHost();
                List<String> linesRequestHeaders = analyzedRequest.getHeaders();
//                stdout.println(linesRequestHeaders);  //RequestHeaders
                Map<String, Object> linesRequestBody = new HashMap<>();
                //Store the decrypted data
                Map<String, Object> linesRequestBodyDecrypted = new HashMap<>();
                List<IParameter> parasListRequest = analyzedRequest.getParameters();
                for (IParameter para : parasListRequest) {
                    String key = para.getName();
                    String value = para.getValue();
                    linesRequestBody.put(key, value);
                }
                stdout.println(linesRequestBody);
                stdout.println("========================= Request Content Stop! ==========================");
            } else {          //if MessageInfo is response
                stdout.println("========================= Response Content Start! ========================");
                String host = messageInfo.getHttpService().getHost();
                Map<String, Object> linesResponseBody = new HashMap<>();
                //Store the decrypted data
                Map<String, Object> linesResponseBodyDecrypted = new HashMap<>();
                byte[] response = messageInfo.getResponse();
                IResponseInfo analyzedResponse = helpers.analyzeResponse(response);
                List<String> linesResponseHeaders = analyzedResponse.getHeaders();
                // stdout.println(linesResponseHeaders); //ResponseHeaders
                if ("JSON".equals(String.valueOf(analyzedResponse.getInferredMimeType()))) {
                    //Get the complete response data
                    String responseBody = null; //Respond to whole packet
                    try {
                        responseBody = new String(messageInfo.getResponse(),"UTF-8");
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    }
                    //The initial offset of the response packet body is obtained by analyzedResponseInfo above
                    int bodyOffset = analyzedResponse.getBodyOffset();
                    //Get the body of the response packet in the response data according to the initial offset of the response data.
                    String content = responseBody.substring(bodyOffset); //Response packet body
                    JSONObject json = JSONObject.parseObject(content);
                    Set<String> parasListResponse = json.keySet();
                    for (String para : parasListResponse) {
                        //stdout.println(JSONObject.parseObject(json.get("data").toString()).get("image1"));
                        if("data".equals(para)){
                            Set<String> dataKey= JSONObject.parseObject(json.getString(para)).keySet();
                            for (String dataPara: dataKey){
                                if ("image1".equals(dataPara)){
                                    json.getJSONObject("data").put("image1", "image1REP");
                                }
                                if ("image2".equals(dataPara)){
                                    json.getJSONObject("data").put("image2", "image2REP");
                                }
                            }
                        }
                    }
                    stdout.println(json);
                } else if ("text".equals(String.valueOf(analyzedResponse.getInferredMimeType()))){
                    //Get the complete response data
                    String responseBody = null; //Respond to whole packet
                    try {
                        responseBody = new String(messageInfo.getResponse(),"UTF-8");
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    }
                    //The initial offset of the response packet body is obtained by analyzedResponseInfo above
                    int bodyOffset = analyzedResponse.getBodyOffset();
                    //Get the body of the response packet in the response data according to the initial offset of the response data.
                    String content = responseBody.substring(bodyOffset); //Response packet body
                    linesResponseBody.put("Encrypt", content);
                    try {
                        String decryptContent = SM4.decryptECB(content,keyBytes);
                        linesResponseBodyDecrypted.put("Decrypt", decryptContent);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    stdout.println(linesResponseBody);
                    stdout.println(linesResponseBodyDecrypted);
                }
                stdout.println("========================= Response Content Stop! =========================");
            }
        }
    }
    private static byte[] hexToBytes(String hexString) {
        int len = hexString.length();
        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i+1), 16));
        }
        return bytes;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02X", b));
        }
        return hexString.toString();
    }
}