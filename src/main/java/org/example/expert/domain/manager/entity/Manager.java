package org.example.expert.domain.manager.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.example.expert.domain.todo.entity.Todo;
import org.example.expert.domain.user.entity.User;

@Getter
@Setter
@Entity
@NoArgsConstructor
@Table(name = "managers")
public class Manager {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "todo_id", nullable = false)
    private Todo todo;

    public Manager(User user, Todo todo) {
        this.user = user;
        this.todo = todo;
    }
}
