//package org.apache.atlas.web.filters;
//
//import javax.servlet.*;
//import javax.servlet.http.HttpServletResponse;
//import java.io.IOException;
//
//public class CORSFilter implements Filter {
//
//    private FilterConfig filterConfig;
//
//    @Override
//    public void init(FilterConfig filterConfig) throws ServletException {
//        this.filterConfig = filterConfig;
//    }
//
//    @Override
//    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
//        HttpServletResponse response = (HttpServletResponse) servletResponse;
//        response.addHeader("Access-Control-Allow-Origin", "*");
//        response.addHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE,OPTIONS");
//        response.addHeader("Access-Control-Allow-Headers", "Content-Type, x-requested-with, X-Custom-Header");
//        response.addHeader("Access-Control-Max-Age", "1800");// 30 min
//        filterChain.doFilter(servletRequest, servletResponse);
//    }
//
//    @Override
//    public void destroy() {
//
//    }
//}
