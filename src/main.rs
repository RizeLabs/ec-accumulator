use ec_accumulator::Bn254Accumulator;
fn main() {
    // Create a new Bn254 accumulator
    let mut acc = Bn254Accumulator::new();

    // Add members to the accumulator
    let member1 = b"member1";
    let member2 = b"member2";
    let member3 = b"member3";

    acc.add_member(member1);
    acc.add_member(member2);
    acc.add_member(member3);

    // Print the current state of the accumulator
    println!("Current Accumulator: {:?}", acc.acc);
}