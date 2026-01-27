use tonic::{Request, Response, Status};

use super::{
    AuthorizationServiceImpl,
    proto::{HealthRequest, HealthResponse},
};

pub async fn health(
    _service: &AuthorizationServiceImpl,
    _request: Request<HealthRequest>,
) -> Result<Response<HealthResponse>, Status> {
    Ok(Response::new(HealthResponse {
        status: "healthy".to_string(),
        service: "inferadb-engine".to_string(),
    }))
}
