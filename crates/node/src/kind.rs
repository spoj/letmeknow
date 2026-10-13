//! The state of a group's kind, handed between members as a file: to a joiner beside its Welcome, and to a member that
//! the kind's own comparison found behind.

use std::sync::Arc;

use anyhow::Result;
use iroh::EndpointId;
use lmk_core::provider::Provider;
use lmk_proto::Bytes;
use lmk_proto::links::FileLink;

use crate::{Event, Inner};

impl<P: Provider + Send + 'static> Inner<P> {
    /// Takes a state `by` handed this session, once it is fetched, and tells the group's kind.
    pub(crate) fn state_from(self: &Arc<Self>, gid: &[u8], link: String, by: EndpointId) {
        let (inner, gid) = (self.clone(), gid.to_vec());
        self.spawn(async move {
            let taken = async {
                let file = FileLink::parse(&link)?;
                {
                    let mut st = inner.lock();
                    st.group_mut(&gid)?.rec.link(link.clone());
                    st.save(&gid)?;
                }
                inner.fetched(&gid, &file).await?;
                let mut data = Vec::new();
                inner.net().read_file(&file, &mut data).await?;
                let mut st = inner.lock();
                let from = st.by_iroh(&gid, &by);
                st.events.push(Event::State { group: Bytes(gid.clone()), from, data });
                anyhow::Ok(())
            };
            if let Err(error) = taken.await {
                inner.warn(Some(&gid), format!("the group's state did not arrive: {error:#}"));
            }
        });
    }

    /// Seals a state of the group's kind as a file to hand a member; holds it.
    pub(crate) async fn state_file(&self, gid: &[u8], data: Vec<u8>) -> Result<String> {
        let link = self.net().add_file(std::io::Cursor::new(data)).await?.link();
        let mut st = self.lock();
        st.group_mut(gid)?.rec.link(link.clone());
        st.save(gid)?;
        Ok(link)
    }
}
