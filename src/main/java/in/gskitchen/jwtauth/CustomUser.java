package in.gskitchen.jwtauth;

public class CustomUser {

    private String name;
    private int id;

    public CustomUser() {
    }

    public CustomUser(String name, int id) {
        this.name = name;
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    @Override
    public String toString() {
        return "CustomUser{" +
                "name='" + name + '\'' +
                ", id=" + id +
                '}';
    }
}
