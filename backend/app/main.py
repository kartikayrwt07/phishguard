"""
PhishGuard Backend Main Application Factory.
"""
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.router import v1_router
from app.core.config import settings
from app.core.exceptions import PhishGuardException
from app.core.logging import configure_logging

logger = logging.getLogger("phishguard.api")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager for startup and shutdown routines."""
    configure_logging(level="DEBUG" if settings.DEBUG else "INFO")
    logger.info("Starting PhishGuard API service", extra={"environment": settings.APP_ENV})
    yield
    logger.info("Shutting down PhishGuard API service")


def create_application() -> FastAPI:
    """Create and configure the production FastAPI application instance."""
    app = FastAPI(
        title="PhishGuard Security API",
        description="Hybrid Browser-Based Phishing Detection & Protection Platform",
        version="1.0.0",
        docs_url="/docs" if settings.DEBUG else None,
        redoc_url="/redoc" if settings.DEBUG else None,
        openapi_url="/openapi.json" if settings.DEBUG else None,
        lifespan=lifespan,
    )

    # 1. CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    # 2. Security Headers Middleware (SEC-02)
    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next) -> Response:
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self' http://localhost:* ws://localhost:*;"
        )
        return response

    # 3. Centralized Exception Handlers (API-07)
    @app.exception_handler(PhishGuardException)
    async def phishguard_exception_handler(request: Request, exc: PhishGuardException) -> JSONResponse:
        logger.warning(
            f"Operational error: {exc.detail}",
            extra={"error_code": exc.error_code, "status_code": exc.status_code, "path": request.url.path},
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.error_code,
                "detail": exc.detail,
                "extra": exc.extra,
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        logger.warning(
            "Request validation failure",
            extra={"path": request.url.path, "errors": exc.errors()},
        )
        return JSONResponse(
            status_code=422,
            content={
                "error": "VALIDATION_ERROR",
                "detail": "Invalid request parameters",
                "errors": exc.errors(),
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error(
            f"Unhandled server error on {request.url.path}: {str(exc)}",
            exc_info=True,
            extra={"path": request.url.path},
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "INTERNAL_SERVER_ERROR",
                "detail": "An internal server error occurred. Please contact the administrator.",
            },
        )

    # 4. Include API Routers
    app.include_router(v1_router)

    return app


app = create_application()
