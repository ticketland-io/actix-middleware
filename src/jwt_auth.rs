use std::{
  future::{ready, Ready as StdReady}, rc::Rc,
};
use actix_web::{
  dev::{forward_ready, Payload, Service, ServiceRequest, ServiceResponse, Transform},
  HttpMessage, FromRequest, Error, HttpRequest, error::ErrorUnauthorized,
};
use futures_util::future::{LocalBoxFuture, ok, err, Ready};
use jsonwebtoken::{decode, Validation, DecodingKey};
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
  pub sub: String,
  pub company: String,
  pub exp: i64,
}

#[derive(Debug, Clone)]
pub struct AuthData {
  pub sub: String,
}

impl FromRequest for AuthData {
  type Error = Error;
  type Future = Ready<Result<Self, Self::Error>>;

  fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
    req.extensions()
    .get::<AuthData>()
    .map(|auth_data| auth_data.clone())
    .map(ok)
    .unwrap_or_else(|| err(ErrorUnauthorized("not authorized")))
  }
}

pub struct AuthnMiddlewareFactory {
  jwt_secret: Rc<String>,
}

impl AuthnMiddlewareFactory {
  pub fn new(jwt_secret: String) -> Self {
    let jwt_secret = Rc::new(
      jwt_secret
    );

    Self {jwt_secret}
  }
}

impl<S, B> Transform<S, ServiceRequest> for AuthnMiddlewareFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthnMiddleware<S>;
    type Future = StdReady<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
      ready(Ok(AuthnMiddleware {
        service: Rc::new(service),
        jwt_secret: self.jwt_secret.clone(),
      }))
    }
}

pub struct AuthnMiddleware<S> {
  service: Rc<S>,
  jwt_secret: Rc<String>,
}

impl<S, B> Service<ServiceRequest> for AuthnMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static
{
  type Response = ServiceResponse<B>;
  type Error = Error;
  type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

  forward_ready!(service);

  fn call(&self, req: ServiceRequest) -> Self::Future {
    let srv = self.service.clone();
    let jwt_secret = self.jwt_secret.clone();

    Box::pin(
      async move {
        let headers = req.headers();
        let bearer = headers.get("Authorization").ok_or(ErrorUnauthorized("Unauthorized"))?;
        
        let mut iter = bearer
        .to_str()
        .map_err(|_| ErrorUnauthorized("Unauthorized"))?
        .split_whitespace();
        
        if let Some(prefix) = iter.next() {
          if prefix != "Bearer" {
            return Err(ErrorUnauthorized("Unauthorized"))
          }
        }

        let access_token = if let Some(access_token) = iter.next() {
          access_token
        } else {
          return Err(ErrorUnauthorized("Unauthorized"))
        };
        
        let validation_result = decode::<Claims>(
          &access_token,
          &DecodingKey::from_secret(jwt_secret.as_bytes()),
          &Validation::default()
        );

        let Ok(token_data) = validation_result else {
          return Err(ErrorUnauthorized("Unauthorized"))
        };

        // make the user available to the downstream handlers
        req.extensions_mut().insert(AuthData {sub: token_data.claims.sub});
  
        return Ok(srv.call(req).await?)
      }
    )
  }
}
