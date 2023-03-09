package com.spring.mvc.interceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

/**
 * @프로젝트명 : AIBK
 * @패키지명 : com.spring.mvc.interceptor
 * @파일명 : ServletInterceptor.java
 * @작성일 : 2023. 2. 20.
 * @작성자 : 김영철
 */
public class ServletInterceptor extends HandlerInterceptorAdapter {

    /**
     * @필드타입 : Logger
     * @필드명 : LOG
     */
    private static final Logger LOG = LogManager.getLogger(ServletInterceptor.class);

    /**
     * @메소드타입 : ServletInterceptor
     */
    protected ServletInterceptor() {
        super();
        LOG.debug("ServletInterceptor ... ");
    }

    /**
     * @메소드타입 : ServletInterceptor
     * @메소드명 : preHandle
     * @param request
     * @param response
     * @param handler
     * @return
     * @throws Exception
     */
    @Override
    public boolean preHandle(final HttpServletRequest request, final HttpServletResponse response, final Object handler)
            throws Exception {
        HttpSession session = request.getSession();
        String uri = request.getRequestURI();
        if (session.getAttribute("login") == null || session.getAttribute("grade") == null) {
            LOG.trace("session attribute null ... ");
            response.sendRedirect("/servlet/user_login");
            return false;
        }

        if (!session.getAttribute("grade").equals("manager") && (uri.equals("/servlet/notice_write")
                || uri.equals("/servlet/notice_update") || uri.equals("/servlet/notice_delete")
                || uri.equals("/servlet/insert_notice") || uri.equals("/servlet/update_notice"))) {
            response.sendRedirect("/servlet/user_login");
            return false;
        }
        return true;
    }
}
