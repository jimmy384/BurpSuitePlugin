package burp.utils;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponsePersisted;
import burp.IResponseInfo;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ResponseClassifier {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;

    // 成功状态码
    private static final Set<Integer> SUCCESS_CODES;

    // 鉴权失败状态码
    private static final Set<Integer> AUTH_FAILURE_CODES;

    static {
        SUCCESS_CODES = new HashSet<>();
        SUCCESS_CODES.add(200);
        SUCCESS_CODES.add(201);
        SUCCESS_CODES.add(202);
        SUCCESS_CODES.add(204);
        AUTH_FAILURE_CODES = new HashSet<>();
        AUTH_FAILURE_CODES.add(401);
        AUTH_FAILURE_CODES.add(403);
        AUTH_FAILURE_CODES.add(407);
    }

    public ResponseClassifier(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    public ResponseType classifyResponse(IHttpRequestResponsePersisted message) {
        try {
            byte[] response = message.getResponse();
            if (response == null) {
                return ResponseType.OTHER;
            }

            IResponseInfo responseInfo = helpers.analyzeResponse(response);
            int statusCode = responseInfo.getStatusCode();

            // 1. 检查是否为成功响应
            if (isSuccessResponse(statusCode, responseInfo)) {
                return ResponseType.SUCCESS;
            }

            // 2. 检查是否为鉴权失败
            if (isAuthFailureResponse(statusCode, responseInfo, response)) {
                return ResponseType.AUTH_FAILURE;
            }

            // 3. 检查是否为普通接口报错
            if (isErrorResponse(statusCode, responseInfo)) {
                return ResponseType.API_ERROR;
            }

            return ResponseType.OTHER;

        } catch (Exception e) {
            callbacks.printError("分类响应时出错: " + e.getMessage());
            return ResponseType.OTHER;
        }
    }

    // 1. 成功的请求
    private boolean isSuccessResponse(int statusCode, IResponseInfo responseInfo) {
        // 状态码在200-299范围内
        if (statusCode >= 200 && statusCode < 300) {
            // 额外的成功特征检查
            return hasSuccessCharacteristics(responseInfo);
        }
        return false;
    }

    private boolean hasSuccessCharacteristics(IResponseInfo responseInfo) {
        // 可以根据需要添加更多的成功特征检查
        return true; // 默认返回true，主要依赖状态码
    }

    // 2. 鉴权失败类的响应
    private boolean isAuthFailureResponse(int statusCode, IResponseInfo responseInfo, byte[] response) {
        // 检查状态码
        if (AUTH_FAILURE_CODES.contains(statusCode)) {
            return true;
        }

        // 检查响应内容中的鉴权失败特征
        if (containsAuthFailureIndicators(responseInfo, response)) {
            return true;
        }

        return false;
    }

    private boolean containsAuthFailureIndicators(IResponseInfo responseInfo, byte[] response) {
        // 获取响应体
        int bodyOffset = responseInfo.getBodyOffset();
        String responseBody = helpers.bytesToString(
                Arrays.copyOfRange(response, bodyOffset, response.length)
        ).toLowerCase();

        // 检查响应体中的鉴权失败关键词
        List<String> authKeywords = Arrays.asList(
                "unauthorized", "forbidden", "access denied", "authentication",
                "login", "token", "api key", "invalid credential", "no permission",
                "权限", "认证", "登录", "令牌"
        );

        for (String keyword : authKeywords) {
            if (responseBody.contains(keyword)) {
                return true;
            }
        }

        return false;
    }

    // 3. 普通接口报错的响应
    private boolean isErrorResponse(int statusCode, IResponseInfo responseInfo) {
        // 客户端错误 (400-499) 和服务器错误 (500-599)
        if ((statusCode >= 400 && statusCode < 500 && !AUTH_FAILURE_CODES.contains(statusCode)) ||
                statusCode >= 500 && statusCode < 600) {
            return true;
        }

        return false;
    }

    // 获取详细的分类信息
    public ClassificationResult getDetailedClassification(IHttpRequestResponsePersisted message) {
        ClassificationResult result = new ClassificationResult();

        try {
            byte[] response = message.getResponse();
            if (response == null) {
                result.setType(ResponseType.OTHER);
                result.setReason("响应为空");
                return result;
            }

            IResponseInfo responseInfo = helpers.analyzeResponse(response);
            result.setStatusCode(responseInfo.getStatusCode());
            result.setHeaders(responseInfo.getHeaders());

            // 获取响应体
            int bodyOffset = responseInfo.getBodyOffset();
            byte[] bodyBytes = Arrays.copyOfRange(response, bodyOffset, response.length);
            result.setBody(helpers.bytesToString(bodyBytes));

            // 分类
            ResponseType type = classifyResponse(message);
            result.setType(type);
            result.setReason(getClassificationReason(type, responseInfo, bodyBytes));

        } catch (Exception e) {
            result.setType(ResponseType.OTHER);
            result.setReason("分类出错: " + e.getMessage());
        }

        return result;
    }

    private String getClassificationReason(ResponseType type, IResponseInfo responseInfo, byte[] body) {
        switch (type) {
            case SUCCESS:
                return "成功状态码: " + responseInfo.getStatusCode();
            case AUTH_FAILURE:
                return "鉴权失败状态码: " + responseInfo.getStatusCode() + " 或包含鉴权失败关键词";
            case API_ERROR:
                return "接口错误状态码: " + responseInfo.getStatusCode();
            default:
                return "未知分类";
        }
    }

    // 响应类型枚举
    public enum ResponseType {
        SUCCESS,        // 成功的请求
        AUTH_FAILURE,   // 鉴权失败
        API_ERROR,      // 普通接口报错
        OTHER          // 其他类型
    }

    // 分类结果类
    public static class ClassificationResult {
        private ResponseType type;
        private int statusCode;
        private List<String> headers;
        private String body;
        private String reason;

        // getters and setters
        public ResponseType getType() {
            return type;
        }

        public void setType(ResponseType type) {
            this.type = type;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public void setStatusCode(int statusCode) {
            this.statusCode = statusCode;
        }

        public List<String> getHeaders() {
            return headers;
        }

        public void setHeaders(List<String> headers) {
            this.headers = headers;
        }

        public String getBody() {
            return body;
        }

        public void setBody(String body) {
            this.body = body;
        }

        public String getReason() {
            return reason;
        }

        public void setReason(String reason) {
            this.reason = reason;
        }
    }
}