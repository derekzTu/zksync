use actix_web::{
    web::{self, Json},
    Scope,
};
use zksync_api_types::OrderWithSignature;
use zksync_storage::ConnectionPool;

use super::{error::Error, response::ApiResult};
use crate::{api_server::tx_sender::TxSender, api_try};

#[derive(Clone)]
struct ApiOrderData {
    tx_sender: TxSender,
}

impl ApiOrderData {
    fn new(tx_sender: TxSender) -> Self {
        Self { tx_sender }
    }
}

async fn submit_order(
    data: web::Data<ApiOrderData>,
    Json(body): Json<OrderWithSignature>,
) -> ApiResult<u64> {
    api_try!(data
        .tx_sender
        .verify_order_eth_signature(&body.order, body.signature.clone())
        .await
        .map_err(Error::from));

    let mut storage = api_try!(data
        .tx_sender
        .pool
        .access_storage()
        .await
        .map_err(Error::storage));
    storage
        .chain()
        .order_schema()
        .store_order(&body)
        .await
        .map_err(Error::storage)
        .into()
}

async fn get_order(
    data: web::Data<ApiOrderData>,
    id: web::Path<u64>,
) -> ApiResult<OrderWithSignature> {
    let mut storage = api_try!(data
        .tx_sender
        .pool
        .access_storage()
        .await
        .map_err(Error::storage));
    storage
        .chain()
        .order_schema()
        .order_by_id(*id)
        .await
        .map_err(Error::storage)
        .into()
}

pub fn api_scope(tx_sender: TxSender) -> Scope {
    let data = ApiOrderData::new(tx_sender);

    web::scope("orders")
        .app_data(web::Data::new(data))
        .route("", web::post().to(submit_order))
        .route("/{id}", web::get().to(get_order))
}
