#[derive(Debug, toasty::Model)]
pub struct Victim {
    #[key]
    pub(crate) id: String,
    pub(crate) hostname: String,
    pub(crate) key: Option<String>,
    pub(crate) code: Option<String>,
    pub(crate) upload_time: Option<i64>,
    pub(crate) complete: bool,
}
