use paillier::*;
use serde::{Deserialize, Serialize};
use serde_json;

#[derive(Debug, Deserialize, Serialize)]
pub struct UserEncryptionKey {
    pub user_id: String,
    pub decryption_key: EncryptionKey,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct KeyPair {
    pub ek: EncryptionKey,
    pub dk: DecryptionKey,
}

impl KeyPair {
    pub fn new() -> Self {
        let (ek, dk) = Paillier::keypair().keys();
        KeyPair { ek, dk }
    }

    pub fn decryption_key_json(&self) -> String {
        serde_json::to_string(&self.dk).unwrap()
    }
}

impl Default for KeyPair {
    fn default() -> Self {
        KeyPair::new()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn new() {
        let key_pair = super::KeyPair::new();
        println!("{:?}", key_pair.ek);
        println!("{:?}", key_pair.dk);
        println!("{}", serde_json::to_string_pretty(&key_pair.ek).unwrap());
        println!("{}", serde_json::to_string_pretty(&key_pair).unwrap());
    }

    #[test]
    fn decryption_key_string() {
        let key_pair = super::KeyPair::new();
        let dk = key_pair.decryption_key_json();
        println!("{}", dk);
    }

    #[test]
    fn serialize() {
        let key_pair = super::KeyPair::new();
        let json = serde_json::to_string(&key_pair).unwrap();
        println!("{}", json);

        let json_string = r#"
        {
            "ek": {
                "n": "18316356530802270868597125126584027114538635007091336571307097048001374334546359767026990171838736786030015500561673293061910747171189548154451794055910096738248464803942158187525599117983095877199615049507683349232319267436471245312899600456912199242319356274382128987298915911903675705364875067572490500358071000763364531740751743813425528436389606184774440631654601835928253705018648484270497224341474039781926254277355160985454809729053601809768728943911255786241347234098406346415245127820068161445975580243992008258832082738229211922479726733190594848509249808820418844044325133001976449187496445656991277029629"
            },
            "dk": {
                "p": "154759743866776248724882635716439025143166826391330822412057810626200572029381153550911287972151524763481007692243073188254156317835057142019935907674250280763179950303592327203210143308948066758516873538039081185972844819822315777562706594850453333318430594764162018001472374655638142250898159531604651584829",
                "q": "151261188036913803234213422098362920421438396753709636863886525143406372619961882944798909281736537591573419840492216749317333719708074682098515275700554764297703668561436456258662156122880199352802129776572451001025865006105240629173136392843016941189901778754984582601377112236507790339002922744597448451731"
            }
        }
        "#;
        let key_pair_de: super::KeyPair = serde_json::from_str(json_string).unwrap();
    }
}
